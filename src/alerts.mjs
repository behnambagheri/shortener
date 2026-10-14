import { timedFetch } from "./screening.mjs";

export function alertsEnabled(env) {
  return Boolean(env.ALERT_WEBHOOK_URL || (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID));
}

// Sends an operator alert to a generic webhook (Slack- and Discord-compatible) and/or Telegram. Never throws.
export async function notify(env, text) {
  const sends = [];
  if (env.ALERT_WEBHOOK_URL) {
    sends.push(timedFetch(env.ALERT_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text, content: text }) }));
  }
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
    sends.push(timedFetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text, disable_web_page_preview: true }),
    }));
  }
  for (const result of await Promise.allSettled(sends)) {
    if (result.status === "rejected" || !result.value.ok) console.warn("An alert could not be delivered.");
  }
}
