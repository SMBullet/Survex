"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, UserSettings, WebhookEntry } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  Settings, Key, Webhook, Plus, Trash2, Save, CheckCircle2,
  AlertCircle, Loader2, Eye, EyeOff, Send, ChevronRight, Brain, Zap,
} from "lucide-react";

function InputField({
  label, value, onChange, placeholder, type = "text", hint,
}: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder?: string; type?: string; hint?: string;
}) {
  const [show, setShow] = useState(false);
  const isPassword = type === "password";

  return (
    <div className="space-y-1.5">
      <label className="block text-[11px] font-bold uppercase tracking-widest text-zinc-600">{label}</label>
      <div className="relative">
        <input
          type={isPassword && !show ? "password" : "text"}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full rounded-lg border border-white/[0.08] bg-[#0a0014] px-3.5 py-2.5 text-[13px] text-zinc-200 placeholder:text-zinc-700 focus:outline-none focus:border-red-500/40 focus:ring-1 focus:ring-red-500/20 transition-all font-mono"
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setShow(s => !s)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400 transition-colors"
          >
            {show ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
          </button>
        )}
      </div>
      {hint && <p className="text-[10px] text-zinc-700">{hint}</p>}
    </div>
  );
}

export default function SettingsPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [settings, setSettings] = useState<UserSettings>({
    shodan_key: "",
    github_token: "",
    webhook_urls: [],
    ai_provider: "",
    ai_api_key: "",
    ai_model: "",
    ai_base_url: "",
  });

  // AI test state
  const [testingAI, setTestingAI] = useState(false);
  const [aiTestResult, setAITestResult] = useState<"ok" | "fail" | null>(null);
  const [saving, setSaving]   = useState(false);
  const [saved, setSaved]     = useState(false);
  const [error, setError]     = useState("");
  const [fetching, setFetching] = useState(true);

  // Webhook test state
  const [testingIdx, setTestingIdx]   = useState<number | null>(null);
  const [testResult, setTestResult]   = useState<Record<number, "ok" | "fail">>({});

  const loadSettings = useCallback(async () => {
    try {
      const s = await api.settings.get();
      setSettings(s);
    } catch { /* ignore */ }
    finally { setFetching(false); }
  }, []);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  useEffect(() => { if (user) loadSettings(); }, [user, loadSettings]);

  const handleSave = async () => {
    setSaving(true);
    setError("");
    setSaved(false);
    try {
      await api.settings.put(settings);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const addWebhook = () => {
    setSettings(s => ({ ...s, webhook_urls: [...s.webhook_urls, { name: "", url: "" }] }));
  };

  const removeWebhook = (i: number) => {
    setSettings(s => ({ ...s, webhook_urls: s.webhook_urls.filter((_, j) => j !== i) }));
    setTestResult(r => { const n = { ...r }; delete n[i]; return n; });
  };

  const updateWebhook = (i: number, field: keyof WebhookEntry, val: string) => {
    setSettings(s => ({
      ...s,
      webhook_urls: s.webhook_urls.map((w, j) => j === i ? { ...w, [field]: val } : w),
    }));
  };

  const testWebhook = async (i: number) => {
    const wh = settings.webhook_urls[i];
    if (!wh.url) return;
    setTestingIdx(i);
    try {
      const res = await fetch(wh.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: "✅ Survex webhook test — connection successful!",
          username: "Survex",
        }),
      });
      setTestResult(r => ({ ...r, [i]: res.ok ? "ok" : "fail" }));
    } catch {
      setTestResult(r => ({ ...r, [i]: "fail" }));
    } finally {
      setTestingIdx(null);
    }
  };

  const testAI = async () => {
    setTestingAI(true);
    setAITestResult(null);
    try {
      await api.ai.query("scan_config", { description: "test connection" });
      setAITestResult("ok");
    } catch {
      setAITestResult("fail");
    } finally {
      setTestingAI(false);
    }
  };

  const AI_PROVIDERS = [
    { id: "pollinations", label: "Free AI",    sub: "No key needed • Pollinations", placeholder: "" },
    { id: "anthropic",    label: "Anthropic",  sub: "Claude Haiku / Sonnet",        placeholder: "sk-ant-…" },
    { id: "openai",       label: "OpenAI",     sub: "GPT-4o / GPT-4o-mini",         placeholder: "sk-…" },
    { id: "deepseek",     label: "DeepSeek",   sub: "deepseek-chat / reasoner",     placeholder: "sk-…" },
    { id: "gemini",       label: "Gemini",     sub: "gemini-1.5-flash / pro",       placeholder: "AIza…" },
    { id: "ollama",       label: "Ollama",     sub: "Local self-hosted model",      placeholder: "none needed" },
  ];

  const selectedProvider = AI_PROVIDERS.find(p => p.id === settings.ai_provider);

  if (loading || !user) return null;

  return (
    <AppShell>
      <main className="min-h-screen bg-[#0d0018] bg-dots">
        <div className="mx-auto max-w-3xl px-6 py-8 space-y-6">

          {/* Header */}
          <div className="flex items-center gap-2 text-xs text-zinc-600">
            <span className="hover:text-zinc-400 cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-zinc-400">Settings</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/[0.08] bg-[#160025]">
              <Settings className="h-5 w-5 text-zinc-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Settings</h1>
              <p className="text-[12px] text-zinc-600">Global API keys and integrations — auto-injected into every scan.</p>
            </div>
          </div>

          {fetching ? (
            <div className="flex items-center gap-3 text-zinc-600 text-sm py-12 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />Loading…
            </div>
          ) : (
            <div className="space-y-5">

              {/* API Keys section */}
              <div className="rounded-xl border border-white/[0.07] bg-[#160025]/60 overflow-hidden">
                <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-white/[0.05] bg-white/[0.015]">
                  <Key className="h-4 w-4 text-zinc-500" />
                  <span className="text-[13px] font-semibold text-white">API Keys</span>
                  <span className="ml-auto text-[10px] text-zinc-700">Stored securely per account · auto-used in scans</span>
                </div>
                <div className="p-5 space-y-5">
                  <InputField
                    label="Shodan API Key"
                    value={settings.shodan_key}
                    onChange={v => setSettings(s => ({ ...s, shodan_key: v }))}
                    placeholder="Enter your Shodan API key…"
                    type="password"
                    hint="Used for host enrichment when 'shodan' module is enabled. Leave blank to skip Shodan."
                  />
                  <InputField
                    label="GitHub Token"
                    value={settings.github_token}
                    onChange={v => setSettings(s => ({ ...s, github_token: v }))}
                    placeholder="ghp_…"
                    type="password"
                    hint="Personal access token with read:org and public_repo scope. Used for GitHub code exposure scanning."
                  />
                </div>
              </div>

              {/* Webhooks section */}
              <div className="rounded-xl border border-white/[0.07] bg-[#160025]/60 overflow-hidden">
                <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-white/[0.05] bg-white/[0.015]">
                  <Webhook className="h-4 w-4 text-zinc-500" />
                  <span className="text-[13px] font-semibold text-white">Webhooks</span>
                  <span className="ml-1 text-[10px] text-zinc-700">Slack · Discord · custom</span>
                  <button
                    onClick={addWebhook}
                    className="ml-auto flex items-center gap-1.5 rounded-md border border-white/[0.07] bg-white/[0.03] px-2.5 py-1.5 text-[11px] font-medium text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.06] transition-all"
                  >
                    <Plus className="h-3 w-3" />
                    Add Webhook
                  </button>
                </div>

                <div className="p-5 space-y-3">
                  {settings.webhook_urls.length === 0 ? (
                    <p className="text-[12px] text-zinc-700 text-center py-4">
                      No webhooks configured. Add a Slack or Discord incoming webhook URL to receive scan alerts.
                    </p>
                  ) : (
                    settings.webhook_urls.map((wh, i) => (
                      <div key={i} className="flex items-start gap-3 rounded-lg border border-white/[0.06] bg-[#0a0014]/60 p-3.5">
                        <div className="flex-1 grid gap-2 sm:grid-cols-[160px_1fr]">
                          <input
                            type="text"
                            value={wh.name}
                            onChange={e => updateWebhook(i, "name", e.target.value)}
                            placeholder="Label (e.g. Slack #alerts)"
                            className="rounded-md border border-white/[0.07] bg-[#160025] px-3 py-2 text-[12px] text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-red-500/40 transition-all"
                          />
                          <input
                            type="url"
                            value={wh.url}
                            onChange={e => updateWebhook(i, "url", e.target.value)}
                            placeholder="https://hooks.slack.com/services/…"
                            className="rounded-md border border-white/[0.07] bg-[#160025] px-3 py-2 text-[12px] font-mono text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-red-500/40 transition-all"
                          />
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0 pt-0.5">
                          {/* Test button */}
                          <button
                            onClick={() => testWebhook(i)}
                            disabled={!wh.url || testingIdx === i}
                            title="Send test payload"
                            className="flex h-8 w-8 items-center justify-center rounded-md border border-white/[0.07] text-zinc-600 hover:text-blue-400 hover:border-blue-500/30 hover:bg-blue-500/8 disabled:opacity-30 transition-all"
                          >
                            {testingIdx === i ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                          </button>
                          {testResult[i] === "ok"   && <CheckCircle2 className="h-4 w-4 text-red-400 shrink-0" />}
                          {testResult[i] === "fail" && <AlertCircle  className="h-4 w-4 text-red-400 shrink-0" />}
                          <button
                            onClick={() => removeWebhook(i)}
                            className="flex h-8 w-8 items-center justify-center rounded-md border border-white/[0.07] text-zinc-600 hover:text-red-400 hover:border-red-500/30 hover:bg-red-500/8 transition-all"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* AI Assistant section */}
              <div className="rounded-xl border border-violet-500/20 bg-[#160025]/60 overflow-hidden">
                <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-white/[0.05] bg-white/[0.015]">
                  <Brain className="h-4 w-4 text-violet-400" />
                  <span className="text-[13px] font-semibold text-white">AI Assistant</span>
                  <span className="ml-auto text-[10px] text-zinc-700">Powers: finding explanations · scan config · executive summaries</span>
                </div>
                <div className="p-5 space-y-5">

                  {/* Provider grid */}
                  <div className="space-y-2">
                    <label className="block text-[11px] font-bold uppercase tracking-widest text-zinc-600">Provider</label>
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                      {AI_PROVIDERS.map(p => {
                        const active = settings.ai_provider === p.id;
                        return (
                          <button
                            key={p.id}
                            type="button"
                            onClick={() => setSettings(s => ({ ...s, ai_provider: p.id, ai_model: "" }))}
                            className={`flex flex-col gap-0.5 rounded-lg border px-3 py-2.5 text-left transition-all ${
                              active
                                ? "border-violet-500/50 bg-violet-500/12 text-violet-300"
                                : "border-white/[0.07] bg-white/[0.02] text-zinc-500 hover:border-white/15 hover:text-zinc-300"
                            }`}
                          >
                            <span className="text-[13px] font-semibold">{p.label}</span>
                            <span className="text-[10px] opacity-60 leading-snug">{p.sub}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {settings.ai_provider && (
                    <div className="grid gap-4 sm:grid-cols-2">
                      {/* API Key */}
                      {settings.ai_provider !== "ollama" && settings.ai_provider !== "pollinations" && (
                        <InputField
                          label="API Key"
                          value={settings.ai_api_key}
                          onChange={v => setSettings(s => ({ ...s, ai_api_key: v }))}
                          placeholder={selectedProvider?.placeholder ?? ""}
                          type="password"
                          hint="Stored securely and never exposed to other users."
                        />
                      )}
                      {settings.ai_provider === "pollinations" && (
                        <div className="flex flex-col gap-1.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3.5 py-3">
                          <span className="text-[11px] font-bold uppercase tracking-widest text-emerald-600">No API Key Required</span>
                          <span className="text-[12px] text-zinc-500">Powered by Pollinations.AI — free, public, no registration. Models: openai (GPT-4o-mini equiv), mistral, llama, openai-large.</span>
                        </div>
                      )}

                      {/* Model */}
                      <InputField
                        label="Model (optional)"
                        value={settings.ai_model}
                        onChange={v => setSettings(s => ({ ...s, ai_model: v }))}
                        placeholder={
                          settings.ai_provider === "anthropic"    ? "claude-haiku-4-5-20251001" :
                          settings.ai_provider === "openai"       ? "gpt-4o-mini" :
                          settings.ai_provider === "deepseek"     ? "deepseek-chat" :
                          settings.ai_provider === "gemini"       ? "gemini-1.5-flash" :
                          settings.ai_provider === "pollinations" ? "openai / mistral / llama" :
                          "llama3.2"
                        }
                        hint="Leave blank to use the provider default."
                      />

                      {/* Base URL for Ollama */}
                      {settings.ai_provider === "ollama" && (
                        <InputField
                          label="Ollama Base URL"
                          value={settings.ai_base_url}
                          onChange={v => setSettings(s => ({ ...s, ai_base_url: v }))}
                          placeholder="http://localhost:11434"
                          hint="Default: http://localhost:11434"
                        />
                      )}
                    </div>
                  )}

                  {/* Test connection */}
                  {settings.ai_provider && (
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        onClick={testAI}
                        disabled={testingAI || (!settings.ai_api_key && settings.ai_provider !== "ollama" && settings.ai_provider !== "pollinations")}
                        className="flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/8 hover:bg-violet-500/15 disabled:opacity-40 px-3.5 py-2 text-[12px] font-medium text-violet-400 transition-all"
                      >
                        {testingAI ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
                        Test Connection
                      </button>
                      {aiTestResult === "ok"   && <span className="flex items-center gap-1.5 text-[12px] text-red-400"><CheckCircle2 className="h-3.5 w-3.5" />Connected</span>}
                      {aiTestResult === "fail" && <span className="flex items-center gap-1.5 text-[12px] text-red-400"><AlertCircle className="h-3.5 w-3.5" />Connection failed — check your key and save first</span>}
                      <span className="ml-auto text-[10px] text-zinc-700">Save settings first, then test</span>
                    </div>
                  )}

                  {!settings.ai_provider && (
                    <p className="text-[12px] text-zinc-700 text-center py-2">
                      Select a provider above to configure AI features. The AI assistant can explain findings, suggest scan configurations, and write executive summaries.
                    </p>
                  )}
                </div>
              </div>

              {/* Save bar */}
              <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-[#160025]/60 px-5 py-3.5">
                {error && (
                  <div className="flex items-center gap-2 text-[12px] text-red-400">
                    <AlertCircle className="h-4 w-4 shrink-0" />
                    {error}
                  </div>
                )}
                {saved && !error && (
                  <div className="flex items-center gap-2 text-[12px] text-red-400">
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    Settings saved.
                  </div>
                )}
                {!error && !saved && <span />}
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 px-4 py-2.5 text-[13px] font-semibold text-white transition-colors"
                >
                  {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                  {saving ? "Saving…" : "Save Settings"}
                </button>
              </div>

            </div>
          )}
        </div>
      </main>
    </AppShell>
  );
}
