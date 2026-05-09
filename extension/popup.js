document.getElementById("unlock").addEventListener("click", () => {
  const password = document.getElementById("masterpass").value;
  if (!password) {
    return;
  }

  chrome.runtime.sendMessage(
    { action: "setMasterPass", password },
    (response) => {
      document.getElementById("status").textContent =
        response.status === "ok" ? "Unlocked!" : "Failed";
    },
  );
});
