// Unit tests talk to the in-browser demo API.
import { registerDemo } from "./api/client";
import { createDemoServer } from "./demo/server";

registerDemo((persona) => createDemoServer({ persona }));
