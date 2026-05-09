let masterPassword = null;
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "setMasterPass") {
    masterPassword = request.password;
    console.log("Master password set");
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
      console.log("tabs:", tabs);
      if (!tabs || tabs.length === 0) {
        console.log("no tabs");
        return;
      }

      const tab = tabs.find((t) => t.url && t.url.startsWith("http"));
      if (!tab) {
        console.log("no http tab found");
        return;
      }

      console.log("using tab:", tab.url);
      const url = new URL(tab.url).hostname;
      console.log("sending to native host for url:", url);

      chrome.runtime.sendNativeMessage(
        "com.lihim.host",
        { action: "get", url: url, masterpass: masterPassword },
        (response) => {
          console.log("native host response:", response);
          if (response?.status === "ok") {
            console.log("sending fill to tab:", tab.id);
            chrome.scripting.executeScript(
              { target: { tabId: tab.id }, files: ["content.js"] },
              () => {
                console.log("content script injected");
                chrome.tabs.sendMessage(
                  tab.id,
                  {
                    action: "fill",
                    username: response.username,
                    password: response.password,
                  },
                  (r) => console.log("fill response:", r),
                );
              },
            );
          }
        },
      );
    });
    sendResponse({ status: "ok" });
    return true;
  }
  if (request.action === "getCredentials") {
    if (!masterPassword) {
      sendResponse({ status: "error", message: "no master password set" });
      return true;
    }
    chrome.runtime.sendNativeMessage(
      "com.lihim.host",
      { action: "get", url: request.url, masterpass: masterPassword },
      (response) => {
        if (chrome.runtime.lastError) {
          sendResponse({
            status: "error",
            message: chrome.runtime.lastError.message,
          });
        } else {
          sendResponse(response);
        }
      },
    );
    return true;
  }
});
