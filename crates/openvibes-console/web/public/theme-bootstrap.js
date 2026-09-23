(function () {
  "use strict";

  var preference = "system";
  try {
    var storedPreference = window.localStorage.getItem("openvibes.theme");
    if (storedPreference === "light" || storedPreference === "dark") {
      preference = storedPreference;
    }
  } catch {
    // Storage can be unavailable under restrictive browser privacy policies.
  }

  var root = document.documentElement;
  root.dataset.themePreference = preference;
  if (preference === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.dataset.theme = preference;
  }

  var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  var dark = preference === "dark" || (preference === "system" && prefersDark);
  var themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) {
    themeColor.setAttribute("content", dark ? "#11171d" : "#f5f4f0");
  }
})();
