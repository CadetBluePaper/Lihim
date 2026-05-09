function findLoginFields() {
  const password = document.querySelector('input[type="password"]');
  if (!password) {
    return null;
  }
  const form = password.closest("form");
  const user = form
    ? form.querySelector('input[type="text"], input[type="email"]')
    : document.querySelector('input[type="text"], input[type="email"]');
  return { user, password };
}

function fillFields(username, password) {
  const fields = findLoginFields();
  if (!fields) {
    return;
  }
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  ).set;

  if (fields.user) {
    setter.call(fields.user, username);
    fields.user.dispatchEvent(new Event("input", { bubbles: true })); // fix: was fields.dispathEvent, wrong object and typo
  }

  setter.call(fields.password, password);
  fields.password.dispatchEvent(new Event("input", { bubbles: true })); // fix: same, wrong object and typo
}

console.log("Lihim content.js loaded on:", window.location.hostname);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("content.js received message:", request);
  if (request.action === "fill") {
    console.log("attempting to fill fields");
    const fields = findLoginFields();
    console.log("fields found:", fields);
    fillFields(request.username, request.password);
  }
});

if (findLoginFields()) {
  chrome.runtime.sendMessage(
    { action: "getCredentials", url: window.location.hostname },
    (response) => {
      if (response?.status === "ok") {
        fillFields(response.username, response.password);
      }
    },
  );
}
