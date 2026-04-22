// Genuine child_process.exec with a user-controlled template literal.
// MUST flag NODE-CMDI-001 critical.
import { exec } from "child_process";

export function listUserDir(user) {
  exec(`ls ${user}`, (err, stdout) => {
    console.log(stdout);
  });
}
