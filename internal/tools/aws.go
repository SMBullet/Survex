package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/SMBullet/Survex/internal/models"
)

// AWSCreds holds credentials for AWS API access.
type AWSCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional — for STS temporary credentials
	RoleARN         string // optional — assume this role first
	Region          string // default: us-east-1
}

// RunAWSReview performs a comprehensive AWS security configuration review.
// It returns findings, the AWS account ID, and any fatal error.
func RunAWSReview(ctx context.Context, creds AWSCreds, logFn func(string)) ([]models.CloudFinding, string, error) {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return nil, "", fmt.Errorf("AWS Access Key ID and Secret Access Key are required")
	}
	if creds.Region == "" {
		creds.Region = "us-east-1"
	}

	// Build base config
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(creds.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
		),
	)
	if err != nil {
		return nil, "", fmt.Errorf("build AWS config: %w", err)
	}

	// If RoleARN specified, assume role
	if creds.RoleARN != "" {
		logFn(fmt.Sprintf("Assuming role: %s", creds.RoleARN))
		stsClient := sts.NewFromConfig(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(stsClient, creds.RoleARN)
	}

	// Get caller identity / account ID
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, "", fmt.Errorf("authenticate with AWS: %w", err)
	}
	accountID := aws.ToString(identity.Account)
	logFn(fmt.Sprintf("Authenticated as account %s", accountID))

	var findings []models.CloudFinding

	// Run checks across services
	logFn("Checking S3 bucket security...")
	findings = append(findings, awsCheckS3(ctx, cfg, logFn)...)

	logFn("Checking IAM security...")
	findings = append(findings, awsCheckIAM(ctx, cfg, logFn)...)

	logFn("Checking EC2 security groups...")
	findings = append(findings, awsCheckEC2(ctx, cfg, creds.Region, logFn)...)

	logFn("Checking RDS instances...")
	findings = append(findings, awsCheckRDS(ctx, cfg, creds.Region, logFn)...)

	logFn("Checking Lambda functions...")
	findings = append(findings, awsCheckLambda(ctx, cfg, creds.Region, logFn)...)

	logFn(fmt.Sprintf("AWS review complete — %d findings", len(findings)))
	return findings, accountID, nil
}

// ── S3 ────────────────────────────────────────────────────────────────────────

func awsCheckS3(ctx context.Context, cfg aws.Config, logFn func(string)) []models.CloudFinding {
	client := s3.NewFromConfig(cfg)
	var findings []models.CloudFinding

	list, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		logFn(fmt.Sprintf("S3 ListBuckets error: %v", err))
		return findings
	}

	logFn(fmt.Sprintf("Found %d S3 buckets", len(list.Buckets)))

	for _, bucket := range list.Buckets {
		name := aws.ToString(bucket.Name)

		// Check public access block
		pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &name})
		if err != nil {
			// If no public access block config exists, that's a finding
			if strings.Contains(err.Error(), "NoSuchPublicAccessBlockConfiguration") {
				findings = append(findings, models.CloudFinding{
					Provider:    "aws",
					Service:     "S3",
					Resource:    name,
					Check:       "Public Access Block Not Configured",
					Detail:      "Bucket has no S3 Public Access Block configuration — public ACLs may be applied.",
					Severity:    "high",
					Remediation: "Enable S3 Block Public Access on the bucket and at the account level.",
				})
			}
		} else if cfg := pab.PublicAccessBlockConfiguration; cfg != nil {
			if !aws.ToBool(cfg.BlockPublicAcls) || !aws.ToBool(cfg.BlockPublicPolicy) ||
				!aws.ToBool(cfg.IgnorePublicAcls) || !aws.ToBool(cfg.RestrictPublicBuckets) {
				findings = append(findings, models.CloudFinding{
					Provider:    "aws",
					Service:     "S3",
					Resource:    name,
					Check:       "Public Access Block Not Fully Enabled",
					Detail:      "One or more S3 Public Access Block settings are disabled.",
					Severity:    "high",
					Remediation: "Enable all four S3 Block Public Access settings for the bucket.",
				})
			}
		}

		// Check bucket ACL
		acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &name})
		if err == nil {
			for _, grant := range acl.Grants {
				if grant.Grantee != nil && grant.Grantee.URI != nil {
					uri := aws.ToString(grant.Grantee.URI)
					if strings.Contains(uri, "AllUsers") {
						findings = append(findings, models.CloudFinding{
							Provider:    "aws",
							Service:     "S3",
							Resource:    name,
							Check:       "Bucket ACL Allows Public Read/Write",
							Detail:      fmt.Sprintf("Bucket grants %s to AllUsers (public internet).", grant.Permission),
							Severity:    "critical",
							Remediation: "Remove public ACL grants and enable S3 Block Public Access.",
						})
					}
				}
			}
		}

		// Check server-side encryption
		enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &name})
		if err != nil || enc.ServerSideEncryptionConfiguration == nil || len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
			findings = append(findings, models.CloudFinding{
				Provider:    "aws",
				Service:     "S3",
				Resource:    name,
				Check:       "Server-Side Encryption Disabled",
				Detail:      "Bucket does not enforce server-side encryption at rest.",
				Severity:    "medium",
				Remediation: "Enable SSE-S3 or SSE-KMS encryption on the bucket.",
			})
		}

		// Check versioning
		ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name})
		if err == nil && (ver.Status == "" || ver.Status == "Suspended") {
			findings = append(findings, models.CloudFinding{
				Provider:    "aws",
				Service:     "S3",
				Resource:    name,
				Check:       "Versioning Disabled",
				Detail:      "Bucket versioning is not enabled. Accidental deletes cannot be recovered.",
				Severity:    "info",
				Remediation: "Enable S3 bucket versioning to protect against accidental deletion.",
			})
		}

		// Check access logging
		log, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &name})
		if err == nil && (log.LoggingEnabled == nil || log.LoggingEnabled.TargetBucket == nil) {
			findings = append(findings, models.CloudFinding{
				Provider:    "aws",
				Service:     "S3",
				Resource:    name,
				Check:       "Access Logging Disabled",
				Detail:      "Bucket does not have server access logging enabled.",
				Severity:    "low",
				Remediation: "Enable S3 server access logging to a dedicated log bucket.",
			})
		}
	}

	return findings
}

// ── IAM ───────────────────────────────────────────────────────────────────────

func awsCheckIAM(ctx context.Context, cfg aws.Config, logFn func(string)) []models.CloudFinding {
	client := iam.NewFromConfig(cfg)
	var findings []models.CloudFinding

	// Check root account access key
	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err == nil {
		if v, ok := summary.SummaryMap["AccountAccessKeysPresent"]; ok && v > 0 {
			findings = append(findings, models.CloudFinding{
				Provider:    "aws",
				Service:     "IAM",
				Resource:    "root",
				Check:       "Root Account Has Active Access Key",
				Detail:      "The AWS root account has active access keys. Root access keys cannot be scoped and are extremely dangerous if compromised.",
				Severity:    "critical",
				Remediation: "Delete root account access keys immediately. Use IAM users or roles instead.",
			})
		}
	}

	// Check password policy
	pp, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil || pp.PasswordPolicy == nil || aws.ToInt32(pp.PasswordPolicy.MinimumPasswordLength) < 14 {
		detail := "No password policy configured."
		if pp != nil && pp.PasswordPolicy != nil {
			detail = fmt.Sprintf("Password minimum length is %d (recommended: 14+).", aws.ToInt32(pp.PasswordPolicy.MinimumPasswordLength))
		}
		findings = append(findings, models.CloudFinding{
			Provider:    "aws",
			Service:     "IAM",
			Resource:    "password-policy",
			Check:       "Weak Password Policy",
			Detail:      detail,
			Severity:    "medium",
			Remediation: "Set IAM password policy: minimum 14 chars, require uppercase, lowercase, numbers, symbols.",
		})
	}

	// List users and check MFA + admin policies + key age
	users, err := client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		logFn(fmt.Sprintf("IAM ListUsers error: %v", err))
		return findings
	}

	logFn(fmt.Sprintf("Checking %d IAM users", len(users.Users)))

	for _, u := range users.Users {
		uname := aws.ToString(u.UserName)

		// Check MFA
		mfaDevices, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: u.UserName})
		if err == nil && len(mfaDevices.MFADevices) == 0 {
			// Check if user has console access
			_, loginErr := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: u.UserName})
			if loginErr == nil { // has console password
				findings = append(findings, models.CloudFinding{
					Provider:    "aws",
					Service:     "IAM",
					Resource:    uname,
					Check:       "Console User Has No MFA",
					Detail:      fmt.Sprintf("IAM user '%s' has console access but no MFA device configured.", uname),
					Severity:    "high",
					Remediation: "Enforce MFA for all IAM users with console access using an SCP or IAM policy condition.",
				})
			}
		}

		// Check for admin policies
		policies, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: u.UserName})
		if err == nil {
			for _, p := range policies.AttachedPolicies {
				if aws.ToString(p.PolicyName) == "AdministratorAccess" {
					findings = append(findings, models.CloudFinding{
						Provider:    "aws",
						Service:     "IAM",
						Resource:    uname,
						Check:       "User Has AdministratorAccess Policy",
						Detail:      fmt.Sprintf("IAM user '%s' has the AdministratorAccess managed policy attached.", uname),
						Severity:    "high",
						Remediation: "Apply least-privilege principle. Use specific IAM policies instead of AdministratorAccess.",
					})
				}
			}
		}

		// Check access key age
		keys, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
		if err == nil {
			for _, k := range keys.AccessKeyMetadata {
				if k.CreateDate == nil {
					continue
				}
				age := time.Since(aws.ToTime(k.CreateDate))
				if age > 90*24*time.Hour {
					findings = append(findings, models.CloudFinding{
						Provider:    "aws",
						Service:     "IAM",
						Resource:    fmt.Sprintf("%s/%s", uname, aws.ToString(k.AccessKeyId)),
						Check:       "Access Key Older Than 90 Days",
						Detail:      fmt.Sprintf("Access key for '%s' is %.0f days old.", uname, age.Hours()/24),
						Severity:    "medium",
						Remediation: "Rotate access keys every 90 days. Use IAM roles where possible.",
					})
				}
			}
		}
	}

	return findings
}

// ── EC2 ───────────────────────────────────────────────────────────────────────

func awsCheckEC2(ctx context.Context, cfg aws.Config, region string, logFn func(string)) []models.CloudFinding {
	client := ec2.NewFromConfig(cfg)
	var findings []models.CloudFinding

	// List all security groups
	sgs, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		logFn(fmt.Sprintf("EC2 DescribeSecurityGroups error: %v", err))
		return findings
	}

	logFn(fmt.Sprintf("Checking %d security groups", len(sgs.SecurityGroups)))

	for _, sg := range sgs.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)
		label := fmt.Sprintf("%s (%s)", sgID, sgName)

		for _, rule := range sg.IpPermissions {
			for _, r := range rule.IpRanges {
				if aws.ToString(r.CidrIp) != "0.0.0.0/0" {
					continue
				}
				from := aws.ToInt32(rule.FromPort)
				to := aws.ToInt32(rule.ToPort)

				if from == 22 && to == 22 {
					findings = append(findings, models.CloudFinding{
						Provider:    "aws",
						Service:     "EC2",
						Resource:    label,
						Check:       "Security Group Allows SSH From Any IP",
						Detail:      "Inbound rule allows TCP port 22 (SSH) from 0.0.0.0/0.",
						Severity:    "critical",
						Remediation: "Restrict SSH access to known IP ranges or use AWS Systems Manager Session Manager.",
					})
				} else if from == 3389 && to == 3389 {
					findings = append(findings, models.CloudFinding{
						Provider:    "aws",
						Service:     "EC2",
						Resource:    label,
						Check:       "Security Group Allows RDP From Any IP",
						Detail:      "Inbound rule allows TCP port 3389 (RDP) from 0.0.0.0/0.",
						Severity:    "critical",
						Remediation: "Restrict RDP access to known IP ranges or use a VPN/bastion host.",
					})
				} else if rule.IpProtocol != nil && aws.ToString(rule.IpProtocol) == "-1" {
					findings = append(findings, models.CloudFinding{
						Provider:    "aws",
						Service:     "EC2",
						Resource:    label,
						Check:       "Security Group Allows All Traffic From Any IP",
						Detail:      "Inbound rule allows all protocols/ports from 0.0.0.0/0.",
						Severity:    "high",
						Remediation: "Apply least-privilege inbound rules. Never use 0.0.0.0/0 for all traffic.",
					})
				} else if from > 0 || to > 0 {
					findings = append(findings, models.CloudFinding{
						Provider:    "aws",
						Service:     "EC2",
						Resource:    label,
						Check:       "Security Group Allows Port Range From Any IP",
						Detail:      fmt.Sprintf("Inbound rule allows ports %d-%d from 0.0.0.0/0.", from, to),
						Severity:    "high",
						Remediation: "Restrict inbound rules to specific source IP ranges.",
					})
				}
			}
			// Check IPv6 open rules
			for _, r := range rule.Ipv6Ranges {
				if aws.ToString(r.CidrIpv6) == "::/0" {
					from := aws.ToInt32(rule.FromPort)
					to := aws.ToInt32(rule.ToPort)
					if from == 22 && to == 22 {
						findings = append(findings, models.CloudFinding{
							Provider:    "aws",
							Service:     "EC2",
							Resource:    label,
							Check:       "Security Group Allows SSH From Any IPv6",
							Detail:      "Inbound rule allows TCP port 22 (SSH) from ::/0.",
							Severity:    "critical",
							Remediation: "Restrict SSH access to known IPv6 ranges.",
						})
					}
				}
			}
		}
	}

	return findings
}

// ── RDS ───────────────────────────────────────────────────────────────────────

func awsCheckRDS(ctx context.Context, cfg aws.Config, region string, logFn func(string)) []models.CloudFinding {
	client := rds.NewFromConfig(cfg)
	var findings []models.CloudFinding

	dbs, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		logFn(fmt.Sprintf("RDS DescribeDBInstances error: %v", err))
		return findings
	}

	logFn(fmt.Sprintf("Checking %d RDS instances", len(dbs.DBInstances)))

	for _, db := range dbs.DBInstances {
		id := aws.ToString(db.DBInstanceIdentifier)

		if aws.ToBool(db.PubliclyAccessible) {
			findings = append(findings, models.CloudFinding{
				Provider:    "aws",
				Service:     "RDS",
				Resource:    id,
				Check:       "RDS Instance Publicly Accessible",
				Detail:      fmt.Sprintf("RDS instance '%s' is configured as publicly accessible.", id),
				Severity:    "high",
				Remediation: "Set PubliclyAccessible=false and place the RDS instance in a private subnet.",
			})
		}

		if !aws.ToBool(db.StorageEncrypted) {
			findings = append(findings, models.CloudFinding{
				Provider:    "aws",
				Service:     "RDS",
				Resource:    id,
				Check:       "RDS Encryption at Rest Disabled",
				Detail:      fmt.Sprintf("RDS instance '%s' does not have storage encryption enabled.", id),
				Severity:    "medium",
				Remediation: "Enable RDS encryption at rest using KMS. Note: encryption must be set at creation time.",
			})
		}

		if db.BackupRetentionPeriod != nil && aws.ToInt32(db.BackupRetentionPeriod) == 0 {
			findings = append(findings, models.CloudFinding{
				Provider:    "aws",
				Service:     "RDS",
				Resource:    id,
				Check:       "RDS Automated Backups Disabled",
				Detail:      fmt.Sprintf("RDS instance '%s' has automated backups disabled (retention = 0 days).", id),
				Severity:    "low",
				Remediation: "Set backup retention period to at least 7 days for RDS instances.",
			})
		}
	}

	return findings
}

// ── Lambda ────────────────────────────────────────────────────────────────────

var awsSensitiveEnvPatterns = []string{
	"SECRET", "KEY", "PASSWORD", "PASSWD", "TOKEN", "CREDENTIAL", "PRIVATE",
}

func awsCheckLambda(ctx context.Context, cfg aws.Config, region string, logFn func(string)) []models.CloudFinding {
	client := lambda.NewFromConfig(cfg)
	var findings []models.CloudFinding

	funcs, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		logFn(fmt.Sprintf("Lambda ListFunctions error: %v", err))
		return findings
	}

	logFn(fmt.Sprintf("Checking %d Lambda functions", len(funcs.Functions)))

	for _, fn := range funcs.Functions {
		name := aws.ToString(fn.FunctionName)

		// Check environment variables for secrets
		if fn.Environment != nil {
			for k, v := range fn.Environment.Variables {
				upper := strings.ToUpper(k)
				for _, pattern := range awsSensitiveEnvPatterns {
					if strings.Contains(upper, pattern) {
						_ = v // don't log the actual value
						findings = append(findings, models.CloudFinding{
							Provider:    "aws",
							Service:     "Lambda",
							Resource:    name,
							Check:       "Potential Secret in Environment Variable",
							Detail:      fmt.Sprintf("Lambda function '%s' has environment variable '%s' that may contain a secret.", name, k),
							Severity:    "high",
							Remediation: "Store secrets in AWS Secrets Manager or Parameter Store (SecureString) instead of Lambda environment variables.",
						})
						break
					}
				}
			}
		}

		// Check resource policy for public access
		policy, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: &name})
		if err == nil && policy.Policy != nil {
			var policyDoc map[string]interface{}
			if json.Unmarshal([]byte(aws.ToString(policy.Policy)), &policyDoc) == nil {
				if stmts, ok := policyDoc["Statement"].([]interface{}); ok {
					for _, stmt := range stmts {
						if s, ok := stmt.(map[string]interface{}); ok {
							if principal, ok := s["Principal"]; ok {
								if p, ok := principal.(string); ok && p == "*" {
									findings = append(findings, models.CloudFinding{
										Provider:    "aws",
										Service:     "Lambda",
										Resource:    name,
										Check:       "Lambda Has Public Resource Policy",
										Detail:      fmt.Sprintf("Lambda function '%s' has a resource policy that allows invocation by anyone (Principal: *).", name),
										Severity:    "high",
										Remediation: "Restrict Lambda resource policy to specific principals (accounts, services, or roles).",
									})
								}
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// awsGetAccountID makes a lightweight STS call to resolve caller identity.
// Used internally when the account ID is not yet available.
func awsGetAccountID(ctx context.Context, cfg aws.Config) string {
	client := sts.NewFromConfig(cfg)
	resp, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return ""
	}
	return aws.ToString(resp.Account)
}

// Ensure unused imports don't cause compile errors.
var (
	_ = ec2types.IpPermission{}
	_ = http.DefaultClient
	_ = io.Discard
)
