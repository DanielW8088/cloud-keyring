import { handleRequest } from "../src/app";
import type { Env } from "../src/types";

export const onRequest: PagesFunction<Env> = ({ request, env }) =>
  handleRequest(request, env);
