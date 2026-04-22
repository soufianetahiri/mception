// Figma plugin sandbox surface: eval should be demoted to MEDIUM (not critical).
figma.showUI(__html__);
figma.ui.onmessage = (msg) => {
  // eslint-disable-next-line no-eval
  const r = eval(msg.expr);
  figma.notify(String(r));
};
