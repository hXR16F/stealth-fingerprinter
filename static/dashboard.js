(function() {
    "use strict";

    const BASE_PATH = window.APP_BASE_PATH || "";

    function copyText(value) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(value);
        }
        var textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand("copy");
        } finally {
            textarea.remove();
        }
        return Promise.resolve();
    }

    document.getElementById("copy-head").addEventListener("click", function () {
        var originalText = this.textContent;

        copyText(originalText).then(() => {
            this.textContent = "COPIED";

            setTimeout(() => {
                this.textContent = originalText;
            }, 800);
        });
    });

    function percentHexEncode(str) {
        var result = '';
        for (var i = 0; i < str.length; i++) {
            var charCode = str.charCodeAt(i);
            if ((charCode >= 97 && charCode <= 122) || (charCode >= 65 && charCode <= 90)) {
                result += '%' + charCode.toString(16).toUpperCase();
            } else {
                result += str[i];
            }
        }
        return result;
    }

    function applyHomoglyphsDisplay(urlStr) {
        return urlStr.replace(/(https?)(:\/\/)/g, function(match, protocol, rest) {
            var homoglyphProtocol = protocol.substring(0, 2) + 'ṭ' + protocol.substring(3);
            return homoglyphProtocol + rest;
        });
    }

    function obfuscateDestinationUrl(urlStr, obfuscationTypes) {
        var result = urlStr;
        var applyHexPercent = obfuscationTypes.indexOf('hex_percent') !== -1;
        var applyDotPercent = obfuscationTypes.indexOf('dot_percent') !== -1;

        if (applyHexPercent || applyDotPercent) {
            try {
                var url = new URL(result);
                var encodedHostname = url.hostname;
                if (applyHexPercent && applyDotPercent) {
                    encodedHostname = percentHexEncode(encodedHostname).replace(/\./g, '%2e');
                } else if (applyHexPercent) {
                    encodedHostname = percentHexEncode(encodedHostname);
                } else if (applyDotPercent) {
                    encodedHostname = encodedHostname.replace(/\./g, '%2e');
                }
                var newResult = url.protocol + '//' + encodedHostname;
                if (url.port) newResult += ':' + url.port;
                if (url.username) {
                    var userinfo = url.username;
                    if (url.password) userinfo += ':' + url.password;
                    newResult = url.protocol + '//' + userinfo + '@' + encodedHostname;
                    if (url.port) newResult += ':' + url.port;
                }
                newResult += url.pathname + url.search + url.hash;
                result = newResult;
            } catch (e) {
                if (result.includes('@')) {
                    var parts = result.split('@');
                    if (parts.length === 2) {
                        var prefix = parts[0];
                        var suffix = parts[1];
                        var slashIndex = suffix.indexOf('/');
                        var hostPart = slashIndex > 0 ? suffix.substring(0, slashIndex) : suffix;
                        var pathPart = slashIndex > 0 ? suffix.substring(slashIndex) : '';
                        var encodedHostPart = hostPart;
                        if (applyHexPercent && applyDotPercent) {
                            encodedHostPart = percentHexEncode(hostPart).replace(/\./g, '%2e');
                        } else if (applyHexPercent) {
                            encodedHostPart = percentHexEncode(hostPart);
                        } else if (applyDotPercent) {
                            encodedHostPart = hostPart.replace(/\./g, '%2e');
                        }
                        var protocolMatch = prefix.match(/^(https?:\/\/)/);
                        if (protocolMatch) {
                            var protocol = protocolMatch[1];
                            var userinfo = prefix.substring(protocol.length);
                            result = protocol + userinfo + '@' + encodedHostPart + pathPart;
                        } else {
                            result = prefix + '@' + encodedHostPart + pathPart;
                        }
                    }
                }
            }
        }
        return result;
    }

    function applyObfuscation(urlStr, obfuscationTypes, obfuscationMethod) {
        var obfuscatedDestination = obfuscateDestinationUrl(urlStr, obfuscationTypes);
        var result = obfuscatedDestination;

        if (obfuscationMethod === 'google_q') {
            result = 'https://www.google.com/url?q=' + encodeURIComponent(obfuscatedDestination);
        } else if (obfuscationMethod === 'google_no_www') {
            result = 'https://google.com/url?q=' + encodeURIComponent(obfuscatedDestination);
        } else if (obfuscationMethod === 'facebook_l') {
            result = 'https://facebook.com/l.php?u=' + encodeURIComponent(obfuscatedDestination);
        } else if (obfuscationMethod === 'auth_google') {
            var destWithoutProtocol = obfuscatedDestination.replace(/^https?:\/\//, '');
            result = 'https://accounts.google.com+signin=secure+v2+identifier=passive@' + destWithoutProtocol;
        } else if (obfuscationMethod === 'auth_facebook') {
            var destWithoutProtocol = obfuscatedDestination.replace(/^https?:\/\//, '');
            result = 'https://facebook.com+login=secure+settings=private@' + destWithoutProtocol;
        } else if (obfuscationMethod === 'auth_instagram') {
            var destWithoutProtocol = obfuscatedDestination.replace(/^https?:\/\//, '');
            result = 'https://instagram.com+accounts=login+settings=private@' + destWithoutProtocol;
        } else if (obfuscationMethod === 'auth_linkedin') {
            var destWithoutProtocol = obfuscatedDestination.replace(/^https?:\/\//, '');
            result = 'https://linkedin.com+accounts=securelogin+settings=private@' + destWithoutProtocol;
        } else if (obfuscationMethod === 'auth_github') {
            var destWithoutProtocol = obfuscatedDestination.replace(/^https?:\/\//, '');
            result = 'https://github.com+login=secure+settings=private@' + destWithoutProtocol;
        }

        return result;
    }

    function getSelectedValues() {
        var obfuscationTypes = [];
        document.querySelectorAll('input[name="obfuscation_types"]:checked').forEach(function(cb) {
            obfuscationTypes.push(cb.value);
        });
        var obfuscationMethod = 'direct';
        document.querySelectorAll('input[name="obfuscation_method"]').forEach(function(r) {
            if (r.checked) obfuscationMethod = r.value;
        });
        var useHomoglyphs = document.getElementById('use_homoglyphs') ? document.getElementById('use_homoglyphs').checked : false;
        return { obfuscationTypes: obfuscationTypes, obfuscationMethod: obfuscationMethod, useHomoglyphs: useHomoglyphs };
    }

    var refreshButton = document.getElementById('refresh-button');
    if (refreshButton) {
        refreshButton.addEventListener('click', function(e) {
            e.preventDefault();
            this.classList.add('spinning');
            window.location.reload();
        });

        refreshButton.addEventListener('animationend', function() {
            this.classList.remove('spinning');
        });
    }

    var behaviorSelect = document.querySelector("[data-behavior-select]");
    var behaviorPanels = document.querySelectorAll("[data-behavior-panel]");
    var botBehaviorSelect = document.querySelector("[data-bot-behavior-select]");
    var botBehaviorPanels = document.querySelectorAll("[data-bot-behavior-panel]");

    function updateBehaviorUI() {
        if (!behaviorSelect) return;
        var behavior = behaviorSelect.value;
        behaviorPanels.forEach(function(panel) {
            var active = panel.dataset.behaviorPanel === behavior;
            panel.hidden = !active;
            var fields = panel.querySelectorAll("[data-behavior-field]");
            for (var i = 0; i < fields.length; i++) {
                fields[i].disabled = !active;
            }
        });
    }

    function updateBotBehaviorUI() {
        if (!botBehaviorSelect) return;
        var behavior = botBehaviorSelect.value;
        botBehaviorPanels.forEach(function(panel) {
            var active = panel.dataset.botBehaviorPanel === behavior;
            panel.hidden = !active;
            var fields = panel.querySelectorAll("[data-bot-behavior-field]");
            for (var i = 0; i < fields.length; i++) {
                fields[i].disabled = !active;
            }
        });
    }

    if (behaviorSelect) {
        behaviorSelect.addEventListener("change", updateBehaviorUI);
    }
    if (botBehaviorSelect) {
        botBehaviorSelect.addEventListener("change", updateBotBehaviorUI);
    }

    updateBehaviorUI();
    updateBotBehaviorUI();

    function toggleDetails(row) {
        var detailsId = row.dataset.details;
        if (!detailsId) return;
        var details = document.getElementById(detailsId);
        if (!details) return;
        var open = details.classList.toggle("open");
        row.setAttribute("aria-expanded", String(open));
    }

    function updateAllEndpointUrls() {
        var values = getSelectedValues();
        var endpointUrlElements = document.querySelectorAll('.endpoint-url-wrap code');
        endpointUrlElements.forEach(function(element) {
            var originalUrl = element.textContent.trim();
            var obfuscatedUrl;
            if (values.obfuscationTypes.length > 0 || values.obfuscationMethod !== 'direct') {
                obfuscatedUrl = applyObfuscation(originalUrl, values.obfuscationTypes, values.obfuscationMethod);
            } else {
                obfuscatedUrl = originalUrl;
            }
            element.dataset.obfuscatedUrl = obfuscatedUrl;
        });
    }

    document.querySelectorAll('input[name="obfuscation_types"]').forEach(function(cb) {
        cb.addEventListener('change', function() { updateAllEndpointUrls(); });
    });

    var homoglyphsCheckbox = document.getElementById('use_homoglyphs');
    if (homoglyphsCheckbox) {
        homoglyphsCheckbox.addEventListener('change', function() { updateAllEndpointUrls(); });
    }

    document.querySelectorAll('input[name="obfuscation_method"]').forEach(function(radio) {
        radio.addEventListener('change', function() { updateAllEndpointUrls(); });
    });

    updateAllEndpointUrls();

    var visitsTable = document.querySelector(".visits-table");
    if (visitsTable) {
        visitsTable.addEventListener("click", function(event) {
            if (event.target.closest("button") || event.target.closest("a") ||
                event.target.closest("input") || event.target.closest("select") ||
                event.target.closest("textarea")) {
                return;
            }
            var row = event.target.closest(".visit-main-row");
            if (row) {
                toggleDetails(row);
            }
        });
    }

    var copyAsOverlay = document.getElementById('copyAsOverlay');
    var copyAsClose = document.getElementById('copyAsClose');
    var copyAsOptions = document.querySelectorAll('.copy-as-option');
    var currentCopyAsTarget = null;
    var currentCopyAsUrl = null;
    var currentObfuscatedUrl = null;
    var currentMimicUrl = null;

    function getMimicUrlFromEndpoint(targetId) {
        var targetElement = document.getElementById(targetId);
        if (!targetElement) return null;
        var row = targetElement.closest('tr');
        if (!row) return null;
        var behaviorCell = row.querySelector('.behavior-cell');
        if (!behaviorCell) return null;
        var strongTag = behaviorCell.querySelector('strong');
        if (!strongTag || strongTag.textContent.trim() !== 'Mimic website') return null;
        var mimicCode = behaviorCell.querySelector('code');
        if (!mimicCode) return null;
        return mimicCode.textContent.trim();
    }

    function openCopyAsModal(targetId, rawUrl, obfuscatedUrl) {
        currentCopyAsTarget = targetId;
        currentCopyAsUrl = rawUrl;
        currentObfuscatedUrl = obfuscatedUrl;
        currentMimicUrl = getMimicUrlFromEndpoint(targetId);
        if (copyAsOverlay) {
            copyAsOverlay.classList.add('open');
        }
    }

    function closeCopyAsModal() {
        if (copyAsOverlay) {
            copyAsOverlay.classList.remove('open');
        }
        currentCopyAsTarget = null;
        currentCopyAsUrl = null;
        currentObfuscatedUrl = null;
        currentMimicUrl = null;
    }

    if (copyAsOverlay) {
        copyAsOverlay.addEventListener('click', function(event) {
            if (event.target === copyAsOverlay) {
                closeCopyAsModal();
            }
        });
    }

    if (copyAsClose) {
        copyAsClose.addEventListener('click', function(event) {
            event.stopPropagation();
            closeCopyAsModal();
        });
    }

    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && copyAsOverlay && copyAsOverlay.classList.contains('open')) {
            closeCopyAsModal();
        }
    });

    var copyAsButtons = document.querySelectorAll(".copy-as-button");
    for (var i = 0; i < copyAsButtons.length; i++) {
        (function(button) {
            button.addEventListener("click", function(event) {
                event.stopPropagation();
                var targetId = button.dataset.copyAsTarget;
                if (!targetId) return;
                var target = document.getElementById(targetId);
                if (!target) return;
                var rawUrl = target.textContent.trim();
                var values = getSelectedValues();
                var obfuscatedUrl;
                if (values.obfuscationTypes.length > 0 || values.obfuscationMethod !== 'direct') {
                    obfuscatedUrl = target.dataset.obfuscatedUrl;
                }
                if (!obfuscatedUrl) {
                    obfuscatedUrl = rawUrl;
                }
                openCopyAsModal(targetId, rawUrl, obfuscatedUrl);
            });
        })(copyAsButtons[i]);
    }

    copyAsOptions.forEach(function(option) {
        option.addEventListener('click', function() {
            var format = this.dataset.copyFormat;
            var rawUrl = currentCopyAsUrl;
            var obfuscatedUrl = currentObfuscatedUrl;
            if (!rawUrl) return;
            var textToCopy = '';
            var useHomoglyphs = document.getElementById('use_homoglyphs') ? document.getElementById('use_homoglyphs').checked : false;
            var urlToUse = rawUrl;
            if (format !== 'raw' && obfuscatedUrl && obfuscatedUrl !== rawUrl) {
                urlToUse = obfuscatedUrl;
            }
            var displayUrl = urlToUse;
            if (currentMimicUrl && format !== 'raw') {
                displayUrl = currentMimicUrl;
            }
            if (useHomoglyphs && format !== 'raw') {
                displayUrl = applyHomoglyphsDisplay(displayUrl);
            }
            switch (format) {
                case 'raw':
                    textToCopy = rawUrl;
                    break;
                case 'markdown':
                    textToCopy = '[' + displayUrl + '](' + urlToUse + ')';
                    break;
                case 'html':
                    textToCopy = '<a href="' + urlToUse + '">' + displayUrl + '</a>';
                    break;
                default:
                    textToCopy = rawUrl;
            }
            copyText(textToCopy).then(function() {
                var originalText = option.textContent;
                option.textContent = 'Copied';
                setTimeout(function() {
                    option.textContent = originalText;
                }, 1000);
                setTimeout(function() {
                    closeCopyAsModal();
                }, 800);
            });
        });
    });

    var copyButtons = document.querySelectorAll(".copy-button");
    for (var i = 0; i < copyButtons.length; i++) {
        (function(button) {
            button.addEventListener("click", function(event) {
                event.stopPropagation();
                var targetId = button.dataset.copyTarget;
                if (!targetId) return;
                var target = document.getElementById(targetId);
                if (!target) return;
                var urlToCopy = target.dataset.obfuscatedUrl || target.textContent.trim();
                copyText(urlToCopy).then(function() {
                    button.textContent = "Copied";
                    setTimeout(function() {
                        button.textContent = "Copy URL";
                    }, 800);
                });
            });
        })(copyButtons[i]);
    }

    var fileInputs = document.querySelectorAll("[data-file-input]");
    for (var i = 0; i < fileInputs.length; i++) {
        (function(input) {
            var name = input.dataset.fileInput;
            var removeButton = document.querySelector('[data-file-remove="' + name + '"]');
            if (!removeButton) return;
            function updateFileButton() {
                removeButton.hidden = !input.files || !input.files.length;
            }
            input.addEventListener("change", updateFileButton);
            removeButton.addEventListener("click", function(event) {
                event.preventDefault();
                input.value = "";
                updateFileButton();
            });
            updateFileButton();
        })(fileInputs[i]);
    }

    var deleteEndpointButtons = document.querySelectorAll("[data-delete-endpoint]");
    for (var i = 0; i < deleteEndpointButtons.length; i++) {
        (function(button) {
            button.addEventListener("click", function(event) {
                event.stopPropagation();
                var endpointId = button.dataset.endpointId;
                if (!endpointId) return;
                if (!confirm("Remove this endpoint?")) return;
                fetch(BASE_PATH + "/delete/" + endpointId, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ delete_visits: false })
                }).then(function(response) {
                    if (response.ok) {
                        location.reload();
                    } else {
                        alert("Failed to delete endpoint.");
                    }
                }).catch(function() {
                    alert("Failed to delete endpoint.");
                });
            });
        })(deleteEndpointButtons[i]);
    }

    var deleteVisitButtons = document.querySelectorAll(".delete-visit-button");
    for (var i = 0; i < deleteVisitButtons.length; i++) {
        (function(button) {
            button.addEventListener("click", function(event) {
                event.stopPropagation();
                var visitId = button.dataset.visitId;
                if (!visitId) return;
                if (!confirm("Delete this visit?")) return;
                fetch(BASE_PATH + "/delete_visit/" + visitId, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" }
                }).then(function(response) {
                    if (response.ok) {
                        location.reload();
                    } else {
                        alert("Failed to delete visit.");
                    }
                }).catch(function() {
                    alert("Failed to delete visit.");
                });
            });
        })(deleteVisitButtons[i]);
    }

    var selectAllCheckbox = document.getElementById("select-all");
    var visitCheckboxes = document.querySelectorAll(".visit-checkbox");
    var deleteMultiButton = document.getElementById("delete-multi");

    function updateDeleteMultiButton() {
        var checked = document.querySelectorAll(".visit-checkbox:checked");
        if (deleteMultiButton) {
            deleteMultiButton.disabled = checked.length === 0;
        }
    }

    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener("change", function() {
            var checked = this.checked;
            visitCheckboxes.forEach(function(cb) {
                cb.checked = checked;
            });
            updateDeleteMultiButton();
        });
    }

    visitCheckboxes.forEach(function(cb) {
        cb.addEventListener("change", function() {
            updateDeleteMultiButton();
        });
    });

    if (deleteMultiButton) {
        deleteMultiButton.addEventListener("click", function() {
            var checked = document.querySelectorAll(".visit-checkbox:checked");
            if (checked.length === 0) return;
            if (!confirm("Delete " + checked.length + " selected visits?")) return;
            var visitIds = [];
            checked.forEach(function(cb) {
                visitIds.push(cb.dataset.visitId);
            });
            fetch(BASE_PATH + "/delete_visits", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ visit_ids: visitIds })
            }).then(function(response) {
                if (response.ok) {
                    location.reload();
                } else {
                    alert("Failed to delete visits.");
                }
            }).catch(function() {
                alert("Failed to delete visits.");
            });
        });
    }

    var hideBotsCheckbox = document.getElementById("hide_bots");
    if (hideBotsCheckbox) {
        hideBotsCheckbox.addEventListener("change", function() {
            var currentUrl = new URL(window.location.href);
            if (this.checked) {
                currentUrl.searchParams.set("hide_bots", "1");
            } else {
                currentUrl.searchParams.delete("hide_bots");
            }
            currentUrl.searchParams.set("page", "1");
            window.location.href = currentUrl.toString();
        });
    }

    var perPageSelect = document.getElementById("per_page");
    if (perPageSelect) {
        perPageSelect.addEventListener("change", function() {
            var currentUrl = new URL(window.location.href);
            currentUrl.searchParams.set("per_page", this.value);
            currentUrl.searchParams.set("page", "1");
            window.location.href = currentUrl.toString();
        });
    }

    var filterButton = document.getElementById("filter-button");
    if (filterButton) {
        filterButton.addEventListener("click", function() {
            var regexFilter = document.getElementById("regex_filter");
            if (regexFilter) {
                var currentUrl = new URL(window.location.href);
                var regexValue = regexFilter.value.trim();
                if (regexValue) {
                    currentUrl.searchParams.set("regex_filter", regexValue);
                } else {
                    currentUrl.searchParams.delete("regex_filter");
                }
                currentUrl.searchParams.set("page", "1");
                window.location.href = currentUrl.toString();
            }
        });
    }

    var filterClear = document.getElementById("filter-clear");
    if (filterClear) {
        filterClear.addEventListener("click", function(event) {
            event.preventDefault();
            var currentUrl = new URL(window.location.href);
            currentUrl.searchParams.delete("regex_filter");
            currentUrl.searchParams.set("page", "1");
            var regexInput = document.getElementById("regex_filter");
            if (regexInput) {
                regexInput.value = "";
            }
            window.location.href = currentUrl.toString();
        });
    }

    var regexInput = document.getElementById("regex_filter");
    if (regexInput) {
        regexInput.addEventListener("keydown", function(event) {
            if (event.key === "Enter") {
                event.preventDefault();
                var filterBtn = document.getElementById("filter-button");
                if (filterBtn) {
                    filterBtn.click();
                }
            }
        });
    }

    var endpointObserver = new MutationObserver(function() {
        updateAllEndpointUrls();
    });
    var endpointWrap = document.querySelector('.endpoint-url-wrap');
    if (endpointWrap) {
        endpointObserver.observe(endpointWrap, { childList: true, subtree: true, characterData: true });
    }

    updateDeleteMultiButton();

})();
