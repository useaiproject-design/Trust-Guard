(function () {
    "use strict";

    function initWorkspace() {
        const results = document.getElementById("results");

        if (!results || results.dataset.workspaceReady === "true") {
            return;
        }

        const originalChildren = Array.from(results.children);

        if (!originalChildren.length) {
            return;
        }

        const workspace = document.createElement("div");
        workspace.className = "tg-workspace";

        const sidebar = document.createElement("aside");
        sidebar.className = "tg-sidebar";
        sidebar.setAttribute("aria-label", "Security navigation");

        sidebar.innerHTML = `
            <div class="tg-sidebar-header">
                <span class="tg-sidebar-kicker">SECURITY WORKSPACE</span>
                <strong>Analysis</strong>
            </div>

            <nav class="tg-nav">

                <button type="button" class="tg-nav-item active" data-target="overview">
                    <span>01</span>
                    <b>Overview</b>
                </button>

                <button type="button" class="tg-nav-item" data-target="profile">
                    <span>02</span>
                    <b>Contract Profile</b>
                </button>

                <button type="button" class="tg-nav-item" data-target="findings">
                    <span>03</span>
                    <b>Security Findings</b>
                </button>

                <button type="button" class="tg-nav-item" data-target="vulnerabilities">
                    <span>04</span>
                    <b>Vulnerabilities</b>
                </button>

                <button type="button" class="tg-nav-item" data-target="remediation">
                    <span>05</span>
                    <b>Remediation</b>
                </button>

                <button type="button" class="tg-nav-item" data-target="deployment">
                    <span>06</span>
                    <b>Deployment</b>
                </button>

                <div class="tg-nav-divider"></div>

                <span class="tg-sidebar-kicker">INTELLIGENCE</span>

                <button type="button" class="tg-nav-item" data-target="onchain">
                    <span>07</span>
                    <b>On-Chain</b>
                </button>

                <button type="button" class="tg-nav-item" data-target="ml">
                    <span>08</span>
                    <b>ML &amp; Explainable AI</b>
                </button>

                <button type="button" class="tg-nav-item" data-target="intelligence">
                    <span>09</span>
                    <b>Security Intelligence</b>
                </button>

                <div class="tg-nav-divider"></div>

                <span class="tg-sidebar-kicker">ASSISTANT</span>

                <button type="button" class="tg-nav-item" data-target="assistant">
                    <span>10</span>
                    <b>AI Assistant</b>
                </button>

            </nav>

            <div class="tg-engine-status">
                <span class="tg-engine-dot"></span>
                <div>
                    <strong>Engine Online</strong>
                    <small>Analysis services ready</small>
                </div>
            </div>
        `;

        const content = document.createElement("div");
        content.className = "tg-workspace-content";

        const panelNames = [
            "overview",
            "profile",
            "findings",
            "vulnerabilities",
            "remediation",
            "deployment",
            "onchain",
            "ml",
            "intelligence",
            "assistant"
        ];

        const panels = {};

        panelNames.forEach(name => {
            const panel = document.createElement("div");
            panel.className = "tg-workspace-panel";
            panel.dataset.panel = name;

            panels[name] = panel;
            content.appendChild(panel);
        });

        const directSections = originalChildren.filter(
            element =>
                element.tagName === "SECTION" &&
                element.classList.contains("dashboard-section")
        );

        const summaryHeading = originalChildren.find(
            element =>
                element.classList &&
                element.classList.contains("section-heading")
        );

        const summaryGrid = originalChildren.find(
            element =>
                element.classList &&
                element.classList.contains("summary-grid")
        );

        if (summaryHeading) {
            panels.overview.appendChild(summaryHeading);
        }

        if (summaryGrid) {
            panels.overview.appendChild(summaryGrid);
        }

        directSections.forEach(section => {
            const heading = section.querySelector(":scope > .section-heading");
            const label = heading
                ? heading.querySelector(".section-label")
                : null;

            const labelText = label
                ? label.textContent.trim().toLowerCase()
                : "";

            const title = heading
                ? heading.querySelector("h2")
                : null;

            const titleText = title
                ? title.textContent.trim().toLowerCase()
                : "";

            if (titleText.includes("contract profile")) {
                panels.profile.appendChild(section);
                return;
            }

            if (titleText.includes("deployment readiness")) {
                panels.deployment.appendChild(section);
                return;
            }

            if (titleText.includes("potential red flags")) {
                panels.findings.appendChild(section);
                return;
            }

            if (titleText.includes("prioritized vulnerabilities")) {
                panels.vulnerabilities.appendChild(section);
                return;
            }

            if (titleText.includes("repair suggestions")) {
                panels.remediation.appendChild(section);
                return;
            }

            if (titleText.includes("on-chain analysis")) {
                panels.onchain.appendChild(section);
                return;
            }

            if (titleText.includes("machine learning") ||
                labelText.includes("ai security intelligence")) {
                panels.ml.appendChild(section);
                return;
            }

            if (titleText.includes("security intelligence details")) {
                panels.intelligence.appendChild(section);
                return;
            }

            if (titleText.includes("ask trustguard ai")) {
                panels.assistant.appendChild(section);
                return;
            }

            if (titleText.includes("security summary")) {
                panels.overview.appendChild(section);
                return;
            }

            panels.intelligence.appendChild(section);
        });

        const mobileBar = document.createElement("div");
        mobileBar.className = "tg-mobile-nav";

        mobileBar.innerHTML = `
            <button type="button" class="tg-mobile-select">
                <span>Current view</span>
                <strong>Overview</strong>
                <span>⌄</span>
            </button>
        `;

        workspace.appendChild(sidebar);
        workspace.appendChild(content);

        results.replaceChildren(mobileBar, workspace);
        results.dataset.workspaceReady = "true";

        const navItems = Array.from(
            sidebar.querySelectorAll(".tg-nav-item")
        );

        function activate(name) {
            navItems.forEach(item => {
                item.classList.toggle(
                    "active",
                    item.dataset.target === name
                );
            });

            Object.entries(panels).forEach(([key, panel]) => {
                panel.classList.toggle("active", key === name);
            });

            const activeItem = navItems.find(
                item => item.dataset.target === name
            );

            if (activeItem) {
                const mobileTitle =
                    mobileBar.querySelector("strong");

                if (mobileTitle) {
                    mobileTitle.textContent =
                        activeItem.querySelector("b")?.textContent ||
                        "Overview";
                }
            }

            sidebar.classList.remove("mobile-open");
        }

        navItems.forEach(item => {
            item.addEventListener("click", () => {
                activate(item.dataset.target);
            });
        });

        const mobileButton =
            mobileBar.querySelector(".tg-mobile-select");

        mobileButton.addEventListener("click", () => {
            sidebar.classList.toggle("mobile-open");
        });

        activate("overview");
    }

    window.TrustGuardWorkspace = {
        init: initWorkspace
    };

    document.addEventListener("DOMContentLoaded", () => {
        const results = document.getElementById("results");

        if (!results) {
            return;
        }

        const observer = new MutationObserver(() => {
            if (
                !results.classList.contains("hidden") &&
                results.children.length &&
                results.dataset.workspaceReady !== "true"
            ) {
                initWorkspace();
            }
        });

        observer.observe(results, {
            attributes: true,
            childList: true
        });
    });
})();
