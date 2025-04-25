function $() {}

$.qs = function(selectors) {
    return document.querySelector(selectors);
};

$.qsa = function(selectors) {
    return document.querySelectorAll(selectors);
};