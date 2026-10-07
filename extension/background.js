// This service worker is currently empty.
// It's required for Manifest V3 extensions but we don't need any background tasks yet.
// You could add logic here for context menus or other features later.
chrome.runtime.onInstalled.addListener(() => {
  console.log('ChainSleuth Extension Installed');
});
    