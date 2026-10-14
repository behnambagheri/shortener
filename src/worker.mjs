import { handle } from "./app.mjs";

export default {
  fetch: (request, env, ctx) => handle(request, env, ctx),
};
