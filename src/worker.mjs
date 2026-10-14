import { handle } from "./app.mjs";
import { runMaintenance } from "./abuse.mjs";

export default {
  fetch: (request, env, ctx) => handle(request, env, ctx, { clientIp: request.headers.get("CF-Connecting-IP") }),
  scheduled: (event, env, ctx) => ctx.waitUntil(runMaintenance(env)),
};
