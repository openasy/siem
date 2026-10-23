// The pages' words, one JSON file per language in messages/, read with i18next through @openasy/ui (its ADR 0006).
// Only English so far: other languages show it until their files are added here.
import { defineMessages } from "@openasy/ui";
import en from "./messages/en.json";

export const useT = defineMessages("siem", { en });
export type T = ReturnType<typeof useT>;
