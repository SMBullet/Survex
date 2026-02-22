"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, AlertCircle } from "lucide-react";

export default function LoginPage() {
  const { login, register } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit =
    (action: "login" | "register") =>
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      setLoading(true);
      try {
        if (action === "login") await login(email, password);
        else await register(email, password);
        router.push("/dashboard");
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "An error occurred");
      } finally {
        setLoading(false);
      }
    };

  return (
    <div className="flex min-h-screen bg-background">
      {/* Left panel – branding */}
      <div className="hidden lg:flex w-1/2 flex-col justify-between bg-zinc-950 dark:bg-zinc-950 light:bg-zinc-900 p-12 text-white">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500">
            <Shield className="h-5 w-5" />
          </div>
          <span className="text-xl font-bold">Survex</span>
        </div>
        <div className="space-y-4">
          <h1 className="text-4xl font-bold leading-tight">
            Attack Surface<br />Management<br />Platform
          </h1>
          <p className="text-zinc-400 text-lg leading-relaxed max-w-md">
            Enumerate subdomains, scan ports, discover vulnerabilities,
            and monitor your external exposure — all from one platform.
          </p>
          <div className="grid grid-cols-2 gap-3 pt-4">
            {[
              ["28+", "Scan Modules"],
              ["Real-time", "Log Streaming"],
              ["HTML", "Reports"],
              ["REST API", "Fully Automated"],
            ].map(([val, label]) => (
              <div key={label} className="rounded-lg border border-zinc-800 p-4">
                <p className="text-emerald-400 font-bold text-lg">{val}</p>
                <p className="text-zinc-400 text-sm">{label}</p>
              </div>
            ))}
          </div>
        </div>
        <p className="text-zinc-600 text-sm">
          Use responsibly. Only scan systems you own or have permission to test.
        </p>
      </div>

      {/* Right panel – form */}
      <div className="flex flex-1 flex-col items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm space-y-8">
          <div className="lg:hidden flex items-center gap-2 mb-8">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-lg font-bold">Survex</span>
          </div>

          <div>
            <h2 className="text-2xl font-bold">Welcome back</h2>
            <p className="text-muted-foreground mt-1">Sign in to your workspace</p>
          </div>

          <Tabs defaultValue="login" className="space-y-6">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="login">Sign In</TabsTrigger>
              <TabsTrigger value="register">Create Account</TabsTrigger>
            </TabsList>

            {(["login", "register"] as const).map((tab) => (
              <TabsContent key={tab} value={tab}>
                <form onSubmit={handleSubmit(tab)} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor={`${tab}-email`}>Email address</Label>
                    <Input
                      id={`${tab}-email`}
                      type="email"
                      placeholder="you@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="email"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor={`${tab}-pw`}>Password</Label>
                    <Input
                      id={`${tab}-pw`}
                      type="password"
                      placeholder={tab === "register" ? "Minimum 8 characters" : "••••••••"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete={tab === "login" ? "current-password" : "new-password"}
                      required
                      minLength={tab === "register" ? 8 : 1}
                    />
                  </div>

                  {error && (
                    <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                      <AlertCircle className="h-4 w-4 shrink-0" />
                      {error}
                    </div>
                  )}

                  <Button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-500 text-white" disabled={loading}>
                    {loading ? "Loading…" : tab === "login" ? "Sign In" : "Create Account"}
                  </Button>
                </form>
              </TabsContent>
            ))}
          </Tabs>
        </div>
      </div>
    </div>
  );
}
