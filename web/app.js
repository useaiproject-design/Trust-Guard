// ============================================================
// TRUSTGUARD AI - WEB DASHBOARD
// Frontend API Integration
// ============================================================


// ============================================================
// API CONFIGURATION
// ============================================================

const API_BASE_URL =
    "http://127.0.0.1:5001";


// ============================================================
// DOM ELEMENTS
// ============================================================

const contractAddressInput =
    document.getElementById(
        "contractAddress"
    );

const analyzeBtn =
    document.getElementById(
        "analyzeBtn"
    );

const loader =
    document.getElementById(
        "loader"
    );

const results =
    document.getElementById(
        "results"
    );

const errorBox =
    document.getElementById(
        "errorBox"
    );

const errorMessage =
    document.getElementById(
        "errorMessage"
    );

const sourceStatus =
    document.getElementById(
        "sourceStatus"
    );

const scoreValue =
    document.getElementById(
        "scoreValue"
    );

const scoreBar =
    document.getElementById(
        "scoreBar"
    );

const riskLevel =
    document.getElementById(
        "riskLevel"
    );

const findingCount =
    document.getElementById(
        "findingCount"
    );

const repairCount =
    document.getElementById(
        "repairCount"
    );

const readinessStatus =
    document.getElementById(
        "readinessStatus"
    );

const readinessScore =
    document.getElementById(
        "readinessScore"
    );

const readinessRisk =
    document.getElementById(
        "readinessRisk"
    );

const readinessFindings =
    document.getElementById(
        "readinessFindings"
    );

const criticalCount =
    document.getElementById(
        "criticalCount"
    );

const highCount =
    document.getElementById(
        "highCount"
    );

const mediumCount =
    document.getElementById(
        "mediumCount"
    );

const lowCount =
    document.getElementById(
        "lowCount"
    );

const infoCount =
    document.getElementById(
        "infoCount"
    );

const blockingIssues =
    document.getElementById(
        "blockingIssues"
    );

const readinessRecommendations =
    document.getElementById(
        "readinessRecommendations"
    );

const flagsList =
    document.getElementById(
        "flagsList"
    );

const vulnerabilitiesList =
    document.getElementById(
        "vulnerabilitiesList"
    );

const repairsList =
    document.getElementById(
        "repairsList"
    );

const onchainDetails =
    document.getElementById(
        "onchainDetails"
    );


// ============================================================
// AI INTELLIGENCE ELEMENTS
// ============================================================

const mlPredictionCount =
    document.getElementById(
        "mlPredictionCount"
    );

const mlFeatureCount =
    document.getElementById(
        "mlFeatureCount"
    );

const shapCount =
    document.getElementById(
        "shapCount"
    );

const limeCount =
    document.getElementById(
        "limeCount"
    );

const mlPredictionsList =
    document.getElementById(
        "mlPredictionsList"
    );

const explanationsList =
    document.getElementById(
        "explanationsList"
    );

const mlFeaturesList =
    document.getElementById(
        "mlFeaturesList"
    );


// ============================================================
// CHAT ELEMENTS
// ============================================================

const chatBox =
    document.getElementById(
        "chatBox"
    );

const chatForm =
    document.getElementById(
        "chatForm"
    );

const chatInput =
    document.getElementById(
        "chatInput"
    );


// ============================================================
// APPLICATION STATE
// ============================================================

let analysisContext = null;


// ============================================================
// ANALYZE BUTTON
// ============================================================

if (analyzeBtn) {

    analyzeBtn.addEventListener(
        "click",
        handleAnalysis
    );

}


// ============================================================
// ENTER KEY SUPPORT
// ============================================================

if (contractAddressInput) {

    contractAddressInput.addEventListener(
        "keydown",
        function (event) {

            if (event.key === "Enter") {

                event.preventDefault();

                handleAnalysis();

            }

        }
    );

}


// ============================================================
// MAIN ANALYSIS FUNCTION
// ============================================================

async function handleAnalysis() {

    const address =
        contractAddressInput.value.trim();


    // --------------------------------------------------------
    // Validate address
    // --------------------------------------------------------

    if (!isValidEthereumAddress(address)) {

        showError(
            "Please enter a valid Ethereum contract address."
        );

        return;

    }


    // --------------------------------------------------------
    // Reset previous state
    // --------------------------------------------------------

    hideError();

    results.classList.add(
        "hidden"
    );

    loader.classList.remove(
        "hidden"
    );

    analyzeBtn.disabled = true;

    analysisContext = null;


    try {

        const data =
            await analyzeContract(
                address
            );


        analysisContext =
            data;


        const intelligence =
            getTrustGuardIntelligence(
                data
            );


        console.info(
            "TrustGuard Intelligence Data Layer:",
            Object.keys(intelligence)
        );


        displayAnalysis(
            data
        );


        resetChat();


    } catch (error) {

        console.error(
            "TrustGuard analysis failed:",
            error
        );


        showError(
            error.message ||
            "Unable to analyze the contract."
        );


    } finally {

        loader.classList.add(
            "hidden"
        );

        analyzeBtn.disabled = false;

    }

}


// ============================================================
// ETHEREUM ADDRESS VALIDATION
// ============================================================

function isValidEthereumAddress(
    address
) {

    return /^0x[a-fA-F0-9]{40}$/.test(
        address
    );

}


// ============================================================
// ANALYZE API REQUEST
// ============================================================

async function analyzeContract(
    address
) {

    const response =
        await fetch(
            `${API_BASE_URL}/analyze`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    contract_address:
                        address

                })

            }
        );


    let data = null;


    try {

        data =
            await response.json();

    } catch (error) {

        throw new Error(
            "The backend returned an invalid response."
        );

    }


    if (!response.ok) {

        throw new Error(
            data.error ||
            `Analysis failed with HTTP ${response.status}.`
        );

    }


    return data;

}


// ============================================================
// TRUSTGUARD INTELLIGENCE DATA ACCESS
// ============================================================

function getIntelligenceSection(
    data,
    section,
    fallback = {}
) {
    if (
        data &&
        typeof data === "object" &&
        data[section] !== null &&
        data[section] !== undefined
    ) {
        return data[section];
    }

    return fallback;
}


function getTrustGuardIntelligence(
    data
) {
    return {
        contractProfile:
            getIntelligenceSection(
                data,
                "contract_profile"
            ),

        securitySummary:
            getIntelligenceSection(
                data,
                "security_summary"
            ),

        attackSurface:
            getIntelligenceSection(
                data,
                "attack_surface"
            ),

        securityEvidence:
            getIntelligenceSection(
                data,
                "security_evidence"
            ),

        mlProbabilityMatrix:
            getIntelligenceSection(
                data,
                "ml_probability_matrix"
            ),

        explanationCenter:
            getIntelligenceSection(
                data,
                "explanation_center"
            ),

        scoreBreakdown:
            getIntelligenceSection(
                data,
                "score_breakdown"
            ),

        analysisPipeline:
            getIntelligenceSection(
                data,
                "analysis_pipeline"
            ),

        vulnerabilityCorrelation:
            getIntelligenceSection(
                data,
                "vulnerability_correlation"
            ),

        confidenceAssessment:
            getIntelligenceSection(
                data,
                "confidence_assessment"
            ),

        limitationsEvidenceNotes:
            getIntelligenceSection(
                data,
                "limitations_evidence_notes"
            ),

        performanceMetrics:
            getIntelligenceSection(
                data,
                "performance_metrics"
            )
    };
}


// ============================================================
// DISPLAY COMPLETE ANALYSIS
// ============================================================

function displayAnalysis(
    data
) {

    results.classList.remove(
        "hidden"
    );


    displaySummary(
        data
    );

    displayContractProfile(
        data.contract_profile
    );

    displaySecuritySummary(
        data.security_summary
    );


    displaySecurityIntelligenceDetails(
        data
    );
    displayReadiness(
        data.deployment_readiness
    );


    displayFlags(
        data.flags
    );


    displayVulnerabilities(
        data.prioritized_vulnerabilities
    );


    displayRepairs(
        data.repair_suggestions
    );


    displayOnchain(
        data.onchain,
        data.liquidity
    );


    // NEW AI INTELLIGENCE
    displayAIIntelligence(
        data.live_intelligence
    );

    if (window.TrustGuardWorkspace) {
        window.TrustGuardWorkspace.init();
    }

}


// ============================================================
// SUMMARY
// ============================================================

function displaySecuritySummary(
    summary
) {

    if (!summary || typeof summary !== "object") {
        return;
    }


    const setText = (
        id,
        value
    ) => {

        const element =
            document.getElementById(id);

        if (element) {
            element.textContent =
                value ?? "-";
        }

    };


    setText(
        "summarySecurityScore",
        summary.security_score !== undefined
            ? `${summary.security_score}/20`
            : "-"
    );


    setText(
        "summaryRiskLevel",
        summary.risk_level
    );


    setText(
        "summaryStaticFindings",
        summary.static_findings_count
    );


    setText(
        "summaryVulnerabilities",
        summary.vulnerability_count
    );


    setText(
        "summaryMLPredictions",
        summary.ml_prediction_count
    );


    setText(
        "summaryCorrelatedFindings",
        summary.correlated_finding_count
    );


    setText(
        "summaryMultiSignal",
        summary.multi_signal_finding_count
    );


    setText(
        "summaryEvidence",
        summary.security_evidence_count
    );

}


function displayContractProfile(
    profile
) {

    if (!profile || typeof profile !== "object") {
        return;
    }


    const setText = (
        id,
        value
    ) => {

        const element =
            document.getElementById(id);

        if (element) {
            element.textContent =
                value ?? "-";
        }

    };


    setText(
        "profileContractAddress",
        profile.contract_address
    );


    setText(
        "profileNetwork",
        profile.network
    );


    setText(
        "profileSourceStatus",
        profile.verified_source
            ? "\u2713"
            : "\u2014"
    );


    setText(
        "profileContractType",
        profile.contract_type
    );


    const upgradeability =
        profile.upgradeability || {};


    setText(
        "profileUpgradeability",
        upgradeability.detected
            ? (
                upgradeability.proxy_pattern
                    ? "Proxy Detected"
                    : "Detected"
            )
            : "Not Detected"
    );


    setText(
        "profileAttackSurface",
        profile.attack_surface_available
            ? "Available"
            : "Unavailable"
    );


    setText(
        "profileOnchain",
        profile.onchain_analysis_available
            ? "Available"
            : "Unavailable"
    );


    setText(
        "profileAnalysisStatus",
        profile.analysis_complete
            ? "Complete"
            : "Incomplete"
    );

}


function displaySecurityIntelligenceDetails(data) {

    const intelligence = getTrustGuardIntelligence(data);

    const render = (id, content) => {
        const element = document.getElementById(id);
        if (element) element.innerHTML = content;
    };

    const title = (key) =>
        String(key)
            .replace(/_/g, " ")
            .replace(/([a-z])([A-Z])/g, "$1 $2")
            .replace(/\b\w/g, c => c.toUpperCase());

    const safe = (value) =>
        escapeHTML(String(value));

    const displayValue = (value) => {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return `<span class="tg-intel-muted">Not available</span>`;
        }

        if (typeof value === "boolean") {
            return value
                ? `<span class="tg-intel-positive">Yes</span>`
                : `<span class="tg-intel-muted">No</span>`;
        }

        if (typeof value === "number") {
            return `<span class="tg-intel-value">${safe(
                Number.isInteger(value)
                    ? value
                    : value.toFixed(4)
            )}</span>`;
        }

        if (typeof value !== "object") {
            return `<span class="tg-intel-value">${safe(value)}</span>`;
        }

        if (Array.isArray(value)) {
            if (!value.length) {
                return `<span class="tg-intel-muted">None identified</span>`;
            }

            return `
                <div class="tg-intel-array">
                    ${value.map((item, index) => `
                        <div class="tg-intel-array-item">
                            <span class="tg-intel-array-index">${index + 1}</span>
                            <div class="tg-intel-array-content">
                                ${
                                    item &&
                                    typeof item === "object"
                                        ? renderObject(item)
                                        : `<span class="tg-intel-value">${safe(item)}</span>`
                                }
                            </div>
                        </div>
                    `).join("")}
                </div>
            `;
        }

        return renderObject(value);
    };

    const emptyState = (
        message = "None identified"
    ) => `
        <span class="tg-intel-muted">
            ${safe(message)}
        </span>
    `;

    const renderObject = (object) => {

        if (
            !object ||
            typeof object !== "object" ||
            Array.isArray(object)
        ) {
            return displayValue(object);
        }

        const entries = Object.entries(object);

        if (!entries.length) {
            return emptyState();
        }

        return `
            <div class="tg-intel-object">
                ${entries.map(([key, value]) => `
                    <div class="tg-intel-row">
                        <span class="tg-intel-key">
                            ${safe(title(key))}
                        </span>
                        <div class="tg-intel-content">
                            ${displayValue(value)}
                        </div>
                    </div>
                `).join("")}
            </div>
        `;
    };

    const renderAnalysisPipeline = (pipeline) => {

        if (!pipeline || typeof pipeline !== "object") {
            return emptyState(
                "Pipeline information not available"
            );
        }

        const stages =
            Array.isArray(pipeline.stages)
                ? pipeline.stages
                : [];

        const total =
            pipeline.total_stages ??
            stages.length;

        const completed =
            pipeline.completed_count ??
            stages.filter(
                stage =>
                    Boolean(
                        stage &&
                        stage.completed
                    )
            ).length;

        const success =
            pipeline.success;

        if (!stages.length) {
            return `
                <div class="tg-intel-pipeline-summary">

                    <div class="tg-intel-pipeline-stat">
                        <span>Status</span>
                        <strong>
                            ${
                                success === true
                                    ? "Completed"
                                    : success === false
                                        ? "Incomplete"
                                        : "Not Available"
                            }
                        </strong>
                    </div>

                    <div class="tg-intel-pipeline-stat">
                        <span>Stages</span>
                        <strong>${safe(total)}</strong>
                    </div>

                </div>
            `;
        }

        return `
            <div class="tg-intel-pipeline">

                <div class="tg-intel-pipeline-summary">

                    <div class="tg-intel-pipeline-stat">
                        <span>Completed</span>
                        <strong>
                            ${safe(completed)} / ${safe(total)}
                        </strong>
                    </div>

                    <div class="tg-intel-pipeline-stat">
                        <span>Pipeline Status</span>
                        <strong>
                            ${
                                success === true
                                    ? "Complete"
                                    : success === false
                                        ? "Incomplete"
                                        : "Unknown"
                            }
                        </strong>
                    </div>

                </div>

                <div class="tg-intel-stage-list">

                    ${stages.map((stage, index) => {

                        const isCompleted =
                            Boolean(
                                stage &&
                                stage.completed
                            );

                        const stageName =
                            stage &&
                            stage.name
                                ? stage.name
                                : `Stage ${index + 1}`;

                        return `
                            <div class="tg-intel-stage">

                                <span class="tg-intel-stage-status ${
                                    isCompleted
                                        ? "completed"
                                        : "pending"
                                }">
                                    ${
                                        isCompleted
                                            ? "\u2713"
                                            : "\u2014"
                                    }
                                </span>

                                <span class="tg-intel-stage-name">
                                    ${safe(stageName)}
                                </span>

                                <span class="tg-intel-stage-state ${
                                    isCompleted
                                        ? "tg-intel-positive"
                                        : "tg-intel-muted"
                                }">
                                    ${
                                        isCompleted
                                            ? "Completed"
                                            : "Not completed"
                                    }
                                </span>

                            </div>
                        `;

                    }).join("")}

                </div>

            </div>
        `;
    };

    const renderCorrelation = (correlation) => {

        if (
            !correlation ||
            typeof correlation !== "object"
        ) {
            return emptyState(
                "Correlation information not available"
            );
        }

        const findings =
            Array.isArray(
                correlation.correlated_findings
            )
                ? correlation.correlated_findings
                : [];

        const correlationCount =
            correlation.correlation_count ??
            findings.length;

        const multiSignalCount =
            correlation.multi_signal_count ??
            findings.filter(
                finding =>
                    Number(
                        finding?.signal_count ?? 0
                    ) >= 2
            ).length;

        const success =
            correlation.success;

        if (!findings.length) {
            return `
                <div class="tg-intel-correlation-summary">

                    <div class="tg-intel-correlation-stat">
                        <span>Correlated Findings</span>
                        <strong>${safe(correlationCount)}</strong>
                    </div>

                    <div class="tg-intel-correlation-stat">
                        <span>Multi-Signal Findings</span>
                        <strong>${safe(multiSignalCount)}</strong>
                    </div>

                    <div class="tg-intel-correlation-stat">
                        <span>Status</span>
                        <strong>
                            ${
                                success === true
                                    ? "Completed"
                                    : success === false
                                        ? "Incomplete"
                                        : "Available"
                            }
                        </strong>
                    </div>

                </div>

                ${
                    correlation.summary
                        ? `
                            <div class="tg-intel-correlation-note">
                                ${safe(correlation.summary)}
                            </div>
                        `
                        : ""
                }
            `;
        }

        return `
            <div class="tg-intel-correlation">

                <div class="tg-intel-correlation-summary">

                    <div class="tg-intel-correlation-stat">
                        <span>Correlated</span>
                        <strong>${safe(correlationCount)}</strong>
                    </div>

                    <div class="tg-intel-correlation-stat">
                        <span>Multi-Signal</span>
                        <strong>${safe(multiSignalCount)}</strong>
                    </div>

                    <div class="tg-intel-correlation-stat">
                        <span>Status</span>
                        <strong>
                            ${
                                success === true
                                    ? "Completed"
                                    : success === false
                                        ? "Incomplete"
                                        : "Available"
                            }
                        </strong>
                    </div>

                </div>

                <div class="tg-intel-correlation-list">

                    ${findings.map((finding, index) => {

                        const vulnerability =
                            finding &&
                            finding.vulnerability
                                ? finding.vulnerability
                                : `Finding ${index + 1}`;

                        const signals =
                            Array.isArray(
                                finding?.signals
                            )
                                ? finding.signals
                                : [];

                        const signalCount =
                            finding?.signal_count ??
                            signals.length;

                        const severity =
                            finding?.severity ||
                            "Not assigned";

                        const level =
                            finding?.correlation_level ||
                            "Unknown";

                        const score =
                            finding?.correlation_score;

                        const confidence =
                            finding?.confidence ||
                            "Unknown";

                        return `
                            <div class="tg-intel-correlation-item">

                                <div class="tg-intel-correlation-header">

                                    <strong>
                                        ${safe(title(vulnerability))}
                                    </strong>

                                    <span class="tg-intel-correlation-level">
                                        ${safe(title(level))}
                                    </span>

                                </div>

                                <div class="tg-intel-correlation-meta">

                                    <div>
                                        <span>Signals</span>
                                        <strong>
                                            ${safe(signalCount)}
                                        </strong>
                                    </div>

                                    <div>
                                        <span>Severity</span>
                                        <strong>
                                            ${safe(title(severity))}
                                        </strong>
                                    </div>

                                    <div>
                                        <span>Confidence</span>
                                        <strong>
                                            ${safe(title(confidence))}
                                        </strong>
                                    </div>

                                    <div>
                                        <span>Correlation Score</span>
                                        <strong>
                                            ${
                                                score !== undefined &&
                                                score !== null
                                                    ? safe(
                                                        Number(score).toFixed(2)
                                                    )
                                                    : "N/A"
                                            }
                                        </strong>
                                    </div>

                                </div>

                                <div class="tg-intel-signal-list">

                                    ${
                                        signals.length
                                            ? signals.map(
                                                signal => `
                                                    <span class="tg-intel-signal">
                                                        ${safe(title(signal))}
                                                    </span>
                                                `
                                            ).join("")
                                            : emptyState(
                                                "No supporting signals"
                                            )
                                    }

                                </div>

                                <div class="tg-intel-correlation-disclaimer">
                                    Correlation indicates supporting evidence
                                    across analysis layers; it does not prove
                                    exploitability.
                                </div>

                            </div>
                        `;

                    }).join("")}

                </div>

                ${
                    correlation.summary
                        ? `
                            <div class="tg-intel-correlation-note">
                                ${safe(correlation.summary)}
                            </div>
                        `
                        : ""
                }

            </div>
        `;
    };

    render(
        "scoreBreakdownDetails",
        renderObject(
            intelligence.scoreBreakdown
        )
    );

    render(
        "confidenceAssessmentDetails",
        renderObject(
            intelligence.confidenceAssessment
        )
    );

    render(
        "analysisPipelineDetails",
        renderAnalysisPipeline(
            intelligence.analysisPipeline
        )
    );

    render(
        "correlationDetails",
        renderCorrelation(
            intelligence.vulnerabilityCorrelation
        )
    );

    render(
        "performanceMetricsDetails",
        renderObject(
            intelligence.performanceMetrics
        )
    );

    if (
        Array.isArray(
            intelligence.limitationsEvidenceNotes
        )
    ) {

        render(
            "limitationsEvidenceDetails",
            intelligence.limitationsEvidenceNotes.length
                ? `
                    <div class="tg-intel-list">

                        ${intelligence.limitationsEvidenceNotes.map(
                            (item, index) => `
                                <div class="tg-intel-list-item">

                                    <span class="tg-intel-number">
                                        ${index + 1}
                                    </span>

                                    <div>
                                        ${displayValue(item)}
                                    </div>

                                </div>
                            `
                        ).join("")}

                    </div>
                `
                : emptyState()
        );

    } else {

        render(
            "limitationsEvidenceDetails",
            renderObject(
                intelligence.limitationsEvidenceNotes
            )
        );

    }

}
function displaySummary(
    data
) {

    const score =
        Number(
            data.score ?? 0
        );


    scoreValue.textContent =
        score;


    const percentage =
        Math.max(
            0,
            Math.min(
                100,
                (score / 20) * 100
            )
        );


    scoreBar.style.width =
        `${percentage}%`;


    riskLevel.textContent =
        data.risk_level ||
        "Unknown";


    riskLevel.style.color =
        getRiskColor(
            data.risk_level
        );


    const findings =
        Array.isArray(
            data.prioritized_vulnerabilities
        )
            ? data.prioritized_vulnerabilities.length
            : 0;


    const repairs =
        Array.isArray(
            data.repair_suggestions
        )
            ? data.repair_suggestions.length
            : 0;


    findingCount.textContent =
        findings;


    repairCount.textContent =
        repairs;


    if (
        data.source_code_available === true
    ) {

        sourceStatus.textContent =
            "\u2713 Source Code Available";

        sourceStatus.style.color =
            "#2ecc71";

    } else {

        sourceStatus.textContent =
            "\u26A0 Source Code Unavailable";

        sourceStatus.style.color =
            "#f1c40f";

    }

}


// ============================================================
// DEPLOYMENT READINESS
// ============================================================

function displayReadiness(
    readiness
) {

    if (!readiness) {

        readinessStatus.textContent =
            "UNKNOWN";

        readinessScore.textContent =
            "-";

        readinessRisk.textContent =
            "-";

        readinessFindings.textContent =
            "0";

        return;

    }


    const status =
        String(
            readiness.status ||
            "UNKNOWN"
        ).toUpperCase();


    readinessStatus.textContent =
        status;


    readinessStatus.className =
        "readiness-status " +
        getReadinessClass(
            status
        );


    readinessScore.textContent =
        `${Number(
            readiness.readiness_score ?? 0
        ).toFixed(1)} / 100`;


    readinessRisk.textContent =
        readiness.risk_level ||
        "UNKNOWN";


    readinessRisk.style.color =
        getRiskColor(
            readiness.risk_level
        );


    readinessFindings.textContent =
        readiness.total_findings ?? 0;


    const counts =
        readiness.vulnerability_counts ||
        {};


    criticalCount.textContent =
        counts.CRITICAL ?? 0;

    highCount.textContent =
        counts.HIGH ?? 0;

    mediumCount.textContent =
        counts.MEDIUM ?? 0;

    lowCount.textContent =
        counts.LOW ?? 0;

    infoCount.textContent =
        counts.INFO ?? 0;


    displayList(
        blockingIssues,
        readiness.blocking_issues,
        "No blocking issues reported."
    );


    displayList(
        readinessRecommendations,
        readiness.recommendations,
        "No additional recommendations."
    );

}


// ============================================================
// RED FLAGS
// ============================================================

function displayFlags(
    flags
) {

    flagsList.innerHTML =
        "";


    if (
        !Array.isArray(flags) ||
        flags.length === 0
    ) {

        flagsList.innerHTML =
            `
            <div class="empty-state">
                No specific red flags were detected.
            </div>
            `;

        return;

    }


    flags.forEach(
        function (flag) {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "flag-card";


            const name =
                escapeHTML(
                    formatName(
                        flag.name ||
                        "Security Flag"
                    )
                );


            const description =
                escapeHTML(
                    flag.description ||
                    "No description available."
                );


            card.innerHTML =
                `
                <strong>
                    ${name}
                </strong>

                <p>
                    ${description}
                </p>
                `;


            flagsList.appendChild(
                card
            );

        }
    );

}


// ============================================================
// PRIORITIZED VULNERABILITIES
// ============================================================

function displayVulnerabilities(
    vulnerabilities
) {

    vulnerabilitiesList.innerHTML =
        "";


    if (
        !Array.isArray(
            vulnerabilities
        ) ||
        vulnerabilities.length === 0
    ) {

        vulnerabilitiesList.innerHTML =
            `
            <div class="empty-state">
                No prioritized vulnerabilities were detected.
            </div>
            `;

        return;

    }


    vulnerabilities.forEach(
        function (
            finding,
            index
        ) {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "finding-card";


            const vulnerability =
                escapeHTML(
                    finding.vulnerability ||
                    "Unknown Vulnerability"
                );


            const severity =
                String(
                    finding.severity ||
                    "INFO"
                ).toUpperCase();


            const probability =
                formatPercentage(
                    finding.probability
                );


            const severityScore =
                Number(
                    finding.severity_score ??
                    0
                ).toFixed(1);


            const priorityScore =
                Number(
                    finding.priority_score ??
                    0
                ).toFixed(1);


            const impact =
                finding.impact ??
                "-";


            const source =
                escapeHTML(
                    finding.source ||
                    "UNKNOWN"
                );


            card.innerHTML =
                `
                <div class="finding-header">

                    <span class="priority">
                        Priority
                        ${finding.priority ?? index + 1}
                    </span>

                    <span
                        class="severity-badge
                        ${getSeverityClass(severity)}"
                    >
                        ${escapeHTML(severity)}
                    </span>

                </div>


                <h3>
                    ${vulnerability}
                </h3>


                <p class="finding-description">

                    Security finding detected by
                    ${source}.

                </p>


                <div class="finding-meta">

                    <div class="meta-item">

                        <span>
                            Probability
                        </span>

                        <strong>
                            ${probability}
                        </strong>

                    </div>


                    <div class="meta-item">

                        <span>
                            Severity Score
                        </span>

                        <strong>
                            ${severityScore}
                        </strong>

                    </div>


                    <div class="meta-item">

                        <span>
                            Impact
                        </span>

                        <strong>
                            ${impact}
                        </strong>

                    </div>


                    <div class="meta-item">

                        <span>
                            Priority Score
                        </span>

                        <strong>
                            ${priorityScore}
                        </strong>

                    </div>

                </div>
                `;


            vulnerabilitiesList.appendChild(
                card
            );

        }
    );

}


// ============================================================
// REPAIR SUGGESTIONS
// ============================================================

function displayRepairs(
    repairs
) {

    repairsList.innerHTML =
        "";


    if (
        !Array.isArray(repairs) ||
        repairs.length === 0
    ) {

        repairsList.innerHTML =
            `
            <div class="empty-state">
                No repair suggestions are currently available.
            </div>
            `;

        return;

    }


    repairs.forEach(
        function (
            repair,
            index
        ) {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "repair-card";


            const title =
                escapeHTML(
                    repair.title ||
                    repair.vulnerability ||
                    "Security Remediation"
                );


            const problem =
                escapeHTML(
                    repair.problem ||
                    "No problem description available."
                );


            const recommendation =
                escapeHTML(
                    repair.recommendation ||
                    "Manual security review recommended."
                );


            const securePattern = repair.secure_pattern ? escapeHTML(String(repair.secure_pattern).replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n").replace(/\\r/g, "\n")) : "";


            card.innerHTML =
                `
                <div class="repair-header">

                    <strong>
                        Priority
                        ${repair.priority ?? index + 1}
                    </strong>


                    ${
                        repair.ai_ready
                            ? `
                            <span class="ai-ready">
                                &#10003; AI Ready
                            </span>
                            `
                            : `
                            <span class="ai-ready">
                                Manual Review
                            </span>
                            `
                    }

                </div>


                <h3>
                    ${title}
                </h3>


                <p>

                    <strong>
                        Problem:
                    </strong>

                    ${problem}

                </p>


                <p>

                    <strong>
                        Recommendation:
                    </strong>

                    ${recommendation}

                </p>


                ${
                    securePattern
                        ? `
                        <pre class="secure-pattern">
${securePattern}
                        </pre>
                        `
                        : ""
                }
                `;


            repairsList.appendChild(
                card
            );

        }
    );

}


// ============================================================
// ON-CHAIN INFORMATION
// ============================================================

function displayOnchain(
    onchain,
    liquidity
) {

    onchainDetails.innerHTML =
        "";


    const totalSupply =
        onchain &&
        onchain.total_supply !== undefined
            ? formatNumber(
                onchain.total_supply
            )
            : "Unavailable";


    const decimals =
        onchain &&
        onchain.decimals !== undefined
            ? onchain.decimals
            : "Unavailable";


    const poolExists =
        liquidity &&
        (
            liquidity.pool_exists === true ||
            liquidity.pool_exists === 1 ||
            liquidity.liquidity_pool_exists === true ||
            liquidity.liquidity_pool_exists === 1
        )
            ? "Pool Found"
            : "No Pool";


    const burnPercentage =
        liquidity &&
        (
            liquidity.burn_percentage !== undefined ||
            liquidity.liquidity_burn_percentage !== undefined
        )
            ? Number(
                liquidity.burn_percentage ??
                liquidity.liquidity_burn_percentage ??
                0
            ).toFixed(6) + "%"
            : "Unavailable";


    addOnchainCard(
        "Total Supply",
        totalSupply
    );


    addOnchainCard(
        "Decimals",
        decimals
    );


    addOnchainCard(
        "Liquidity Pool",
        poolExists
    );


    addOnchainCard(
        "LP Burn Percentage",
        burnPercentage
    );

}


// ============================================================
// ON-CHAIN CARD
// ============================================================

function addOnchainCard(
    label,
    value
) {

    const card =
        document.createElement(
            "div"
        );


    card.className =
        "onchain-card";


    card.innerHTML =
        `
        <span>
            ${escapeHTML(label)}
        </span>

        <strong>
            ${escapeHTML(
                String(value)
            )}
        </strong>
        `;


    onchainDetails.appendChild(
        card
    );

}


// ============================================================
// AI INTELLIGENCE
// ============================================================

function displayAIIntelligence(
    live
) {

    // --------------------------------------------------------
    // Reset
    // --------------------------------------------------------

    if (mlPredictionCount) {
        mlPredictionCount.textContent =
            "0";
    }

    if (mlFeatureCount) {
        mlFeatureCount.textContent =
            "0";
    }

    const mlClassesElement =
        document.getElementById(
            "mlClassesEvaluated"
        );

    if (mlClassesElement) {
        mlClassesElement.textContent =
            "0";
    }

    if (shapCount) {
        shapCount.textContent =
            "0";
    }

    if (limeCount) {
        limeCount.textContent =
            "0";
    }


    if (mlPredictionsList) {
        mlPredictionsList.innerHTML =
            "";
    }

    if (explanationsList) {
        explanationsList.innerHTML =
            "";
    }

    if (mlFeaturesList) {
        mlFeaturesList.innerHTML =
            "";
    }


    // --------------------------------------------------------
    // No live intelligence
    // --------------------------------------------------------

    if (
        !live ||
        typeof live !== "object"
    ) {

        renderAIEmptyState(
            mlPredictionsList,
            "Live machine-learning results are not available."
        );

        renderAIEmptyState(
            explanationsList,
            "SHAP and LIME explanations are not available."
        );

        renderAIEmptyState(
            mlFeaturesList,
            "Security features are not available."
        );

        return;

    }


    // --------------------------------------------------------
    // Backend error
    // --------------------------------------------------------

    if (live.error) {

        renderAIEmptyState(
            mlPredictionsList,
            "AI intelligence could not be generated."
        );

        renderAIEmptyState(
            explanationsList,
            String(
                live.error
            )
        );

        renderAIEmptyState(
            mlFeaturesList,
            "Feature extraction was unavailable."
        );

        return;

    }


    // --------------------------------------------------------
    // Extract data
    // --------------------------------------------------------

    const predictions =
        Array.isArray(
            live.ml_predictions
        )
            ? live.ml_predictions
            : [];



    const explanations =
        live.explanations &&
        typeof live.explanations === "object"
            ? live.explanations
            : {};

    const features =
        live.features &&
        typeof live.features === "object"
            ? live.features
            : {};


    // --------------------------------------------------------
    // Summary counters
    // --------------------------------------------------------

    const detectedPredictions =
        predictions.filter(
            prediction =>
                Boolean(
                    prediction.detected
                )
        );


    if (mlPredictionCount) {

        mlPredictionCount.textContent =
            detectedPredictions.length;

    }


    if (mlFeatureCount) {

        mlFeatureCount.textContent =
            live.feature_count ??
            Object.keys(
                features
            ).length;

    }

    // ML classes evaluated by the prediction engine.
    // This is intentionally separate from detected vulnerabilities.
    const evaluatedClassCount =
        predictions.length;

    if (mlClassesElement) {

        mlClassesElement.textContent =
            evaluatedClassCount;

    }


    // --------------------------------------------------------
    // Count SHAP / LIME explanations
    // Backend returns:
    // explanations = {
    //     "shap": {
    //         "Access Control": [...],
    //         "Arithmetic": [...],
    //         ...
    //     },
    //     "lime": {
    //         "Access Control": [...],
    //         "Arithmetic": [...],
    //         ...
    //     }
    // }
    // --------------------------------------------------------

    let shapTotal = 0;
    let limeTotal = 0;

    if (
        live.explanations &&
        typeof live.explanations === "object"
    ) {

        const shapExplanations =
            live.explanations.shap;

        const limeExplanations =
            live.explanations.lime;

        if (
            shapExplanations &&
            typeof shapExplanations === "object"
        ) {
            shapTotal =
                Object.keys(
                    shapExplanations
                ).filter(
                    key =>
                        shapExplanations[key] &&
                        !shapExplanations[key].error
                ).length;
        }

        if (
            limeExplanations &&
            typeof limeExplanations === "object"
        ) {
            limeTotal =
                Object.keys(
                    limeExplanations
                ).filter(
                    key =>
                        limeExplanations[key] &&
                        !limeExplanations[key].error
                ).length;
        }
    }


    if (shapCount) {

        shapCount.textContent =
            shapTotal;

    }


    if (limeCount) {

        limeCount.textContent =
            limeTotal;

    }


    // --------------------------------------------------------
    // Render predictions
    // --------------------------------------------------------

    renderMLPredictions(
        predictions
    );


    // --------------------------------------------------------
    // Render explanations
    // --------------------------------------------------------

    renderExplanations(
        explanations
    );


    // --------------------------------------------------------
    // Render features
    // --------------------------------------------------------

    renderMLFeatures(
        features
    );

}


// ============================================================
// ML PREDICTIONS
// ============================================================

function renderMLPredictions(
    predictions
) {

    if (!mlPredictionsList) {
        return;
    }


    mlPredictionsList.innerHTML =
        "";


    if (
        !Array.isArray(predictions) ||
        predictions.length === 0
    ) {

        renderAIEmptyState(
            mlPredictionsList,
            "No machine-learning predictions were returned."
        );

        return;

    }


    // Detected vulnerabilities first,
    // then highest probability.

    const ordered =
        [...predictions].sort(
            function (a, b) {

                const detectedDifference =
                    Number(
                        Boolean(b.detected)
                    ) -
                    Number(
                        Boolean(a.detected)
                    );


                if (
                    detectedDifference !== 0
                ) {

                    return detectedDifference;

                }


                return (
                    Number(
                        b.probability || 0
                    ) -
                    Number(
                        a.probability || 0
                    )
                );

            }
        );


    ordered.forEach(
        function (prediction) {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "finding-card";


            const name =
                escapeHTML(
                    formatName(
                        prediction.id ||
                        prediction.vulnerability ||
                        "Unknown"
                    )
                );


            const probability =
                formatPercentage(
                    prediction.probability
                );


            const severity =
                String(
                    prediction.severity ||
                    "INFO"
                ).toUpperCase();


            const detected =
                Boolean(
                    prediction.detected
                );


            const severityScore = prediction.severity_score !== undefined && prediction.severity_score !== null ? Number(prediction.severity_score).toFixed(1) : "Not assigned";


            card.innerHTML =
                `
                <div class="finding-header">

                    <span class="priority">

                        ${
                            detected
                                ? "DETECTED"
                                : "MODEL SIGNAL"
                        }

                    </span>


                    <span
                        class="severity-badge
                        ${getSeverityClass(severity)}"
                    >
                        ${escapeHTML(severity)}
                    </span>

                </div>


                <h3>
                    ${name}
                </h3>


                <div class="finding-meta">


                    <div class="meta-item">

                        <span>
                            Probability
                        </span>

                        <strong>
                            ${probability}
                        </strong>

                    </div>


                    <div class="meta-item">

                        <span>
                            Severity Score
                        </span>

                        <strong>
                            ${severityScore}
                        </strong>

                    </div>


                    <div class="meta-item">

                        <span>
                            Impact
                        </span>

                        <strong>
                            ${prediction.impact ?? "Not assessed"}
                        </strong>

                    </div>


                    <div class="meta-item">

                        <span>
                            Exploitability
                        </span>

                        <strong>
                            ${prediction.exploitability ?? "Not assessed"}
                        </strong>

                    </div>


                </div>


                <p class="finding-description">

                    ${
                        detected
                            ? "The machine-learning pipeline detected this vulnerability pattern."
                            : "The model evaluated this vulnerability class but did not mark it as detected."
                    }

                </p>
                `;


            mlPredictionsList.appendChild(
                card
            );

        }
    );

}


// ============================================================
// SHAP + LIME EXPLANATIONS
// ============================================================

function extractExplanationItems(
    explanation
) {
    if (!explanation || typeof explanation !== "object") {
        return [];
    }
    if (Array.isArray(explanation)) {
        return explanation;
    }

    const candidates = [
        explanation.features,
        explanation.top_features,
        explanation.feature_importance,
        explanation.importance,
        explanation.explanation,
        explanation.values
    ];

    for (const candidate of candidates) {
        if (Array.isArray(candidate)) {
            return candidate;
        }
        if (candidate && typeof candidate === "object") {
            return Object.entries(candidate).map(([feature, value]) => ({
                feature: feature,
                value: value
            }));
        }
    }

    return [];
}


function renderExplanations(
    explanations
) {
    if (!explanationsList) {
        return;
    }

    explanationsList.innerHTML = "";

    if (
        !explanations ||
        typeof explanations !== "object"
    ) {
        renderAIEmptyState(
            explanationsList,
            "No SHAP or LIME explanations were generated for this analysis."
        );
        return;
    }

    const shap =
        explanations.shap &&
        typeof explanations.shap === "object"
            ? explanations.shap
            : {};

    const lime =
        explanations.lime &&
        typeof explanations.lime === "object"
            ? explanations.lime
            : {};

    const items = [];

    Object.entries(shap).forEach(
        ([vulnerability, value]) => {
            if (
                value &&
                typeof value === "object" &&
                !value.error
            ) {
                items.push({
                    method: "SHAP",
                    vulnerability: vulnerability,
                    value: value
                });
            }
        }
    );

    Object.entries(lime).forEach(
        ([vulnerability, value]) => {
            if (
                value &&
                typeof value === "object" &&
                !value.error
            ) {
                items.push({
                    method: "LIME",
                    vulnerability: vulnerability,
                    value: value
                });
            }
        }
    );

    if (items.length === 0) {
        renderAIEmptyState(
            explanationsList,
            "No valid SHAP or LIME explanations were generated for this analysis."
        );
        return;
    }

    items.forEach(function (item) {
        const wrapper =
            document.createElement("div");

        wrapper.className =
            "finding-card";

        const explanationItems =
            extractExplanationItems(
                item.value
            );

        let explanationHTML = "";

        if (
            Array.isArray(explanationItems) &&
            explanationItems.length
        ) {
            explanationHTML =
                explanationItems
                    .slice(0, 8)
                    .map(function (entry) {
                        const feature =
                            entry.feature ??
                            entry.name ??
                            "Feature";

                        const impact =
                            entry.impact ??
                            entry.value ??
                            entry.contribution ??
                            "";

                        return `
                            <div class="explanation-row">
                                <span>${escapeHTML(String(feature))}</span>
                                <strong>${escapeHTML(String(impact))}</strong>
                            </div>
                        `;
                    })
                    .join("");
        } else {
            explanationHTML = `
                <div class="explanation-row">
                    <span>Explanation generated successfully</span>
                    <strong>${escapeHTML(
                        JSON.stringify(item.value)
                    )}</strong>
                </div>
            `;
        }

        wrapper.innerHTML = `
            <div class="finding-header">
                <div>
                    <span class="finding-label">
                        ${escapeHTML(item.method)}
                    </span>
                    <h3>
                        ${escapeHTML(item.vulnerability)}
                    </h3>
                </div>
            </div>

            <div class="finding-details">
                ${explanationHTML}
            </div>
        `;

        explanationsList.appendChild(
            wrapper
        );
    });
}


// ============================================================
// EXPLANATION ITEM EXTRACTION
// ============================================================

function renderExplanationItems(
    explanation,
    type
) {

    if (
        !explanation ||
        typeof explanation !== "object"
    ) {

        return `
            <p>
                No ${type} data available.
            </p>
        `;

    }


    // Different explainers may expose
    // their feature data using slightly
    // different property names.

    const candidates = [

        explanation.features,

        explanation.top_features,

        explanation.feature_importance,

        explanation.importance,

        explanation.explanation,

        explanation.values

    ];


    let items = null;


    for (
        const candidate of candidates
    ) {

        if (
            Array.isArray(candidate)
        ) {

            items =
                candidate;

            break;

        }


        if (
            candidate &&
            typeof candidate === "object"
        ) {

            items =
                Object.entries(
                    candidate
                ).map(
                    function (
                        [
                            feature,
                            value
                        ]
                    ) {

                        return {
                            feature,
                            value
                        };

                    }
                );

            break;

        }

    }


    if (
        !items ||
        items.length === 0
    ) {

        return `
            <p>
                ${type} explanation generated,
                but no feature values were returned.
            </p>
        `;

    }


    return `

        <div class="ai-feature-list">

            ${items
                .slice(0, 8)
                .map(
                    function (item) {

                        let feature =
                            item.feature ||
                            item.name ||
                            item.feature_name ||
                            item[0] ||
                            "Feature";


                        let value =
                            item.value ??
                            item.importance ??
                            item.weight ??
                            item.contribution ??
                            item[1] ??
                            "";


                        feature =
                            escapeHTML(
                                formatName(
                                    feature
                                )
                            );


                        value =
                            escapeHTML(
                                formatExplanationValue(
                                    value
                                )
                            );


                        return `
                            <div class="ai-feature-row">

                                <span>
                                    ${feature}
                                </span>

                                <strong>
                                    ${value}
                                </strong>

                            </div>
                        `;

                    }
                )
                .join("")}

        </div>

    `;

}


// ============================================================
// ML FEATURES
// ============================================================

function renderMLFeatures(
    features
) {

    if (!mlFeaturesList) {
        return;
    }


    mlFeaturesList.innerHTML =
        "";


    if (
        !features ||
        typeof features !== "object" ||
        Object.keys(features).length === 0
    ) {

        renderAIEmptyState(
            mlFeaturesList,
            "No engineered security features were returned."
        );

        return;

    }


    Object.entries(
        features
    ).forEach(
        function (
            [
                name,
                value
            ]
        ) {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "onchain-card";


            card.innerHTML =
                `
                <span>
                    ${escapeHTML(
                        formatName(name)
                    )}
                </span>


                <strong>

                    ${escapeHTML(
                        formatFeatureValue(
                            value
                        )
                    )}

                </strong>
                `;


            mlFeaturesList.appendChild(
                card
            );

        }
    );

}


// ============================================================
// AI EMPTY STATE
// ============================================================

function renderAIEmptyState(
    element,
    message
) {

    if (!element) {
        return;
    }


    element.innerHTML =
        `
        <div class="empty-state">

            ${escapeHTML(
                message
            )}

        </div>
        `;

}


// ============================================================
// FORMAT FEATURE VALUE
// ============================================================

function formatFeatureValue(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {

        return "-";

    }


    if (
        typeof value === "number"
    ) {

        if (
            Number.isInteger(value)
        ) {

            return value.toLocaleString(
                "en-US"
            );

        }


        return value.toFixed(4);

    }


    return String(
        value
    );

}


// ============================================================
// FORMAT EXPLANATION VALUE
// ============================================================

function formatExplanationValue(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {

        return "-";

    }


    if (
        typeof value === "number"
    ) {

        return value.toFixed(4);

    }


    if (
        typeof value === "object"
    ) {

        return JSON.stringify(
            value
        );

    }


    return String(
        value
    );

}


// ============================================================
// CHAT FORM
// ============================================================

if (chatForm) {

    chatForm.addEventListener(
        "submit",
        handleChat
    );

}


// ============================================================
// CHAT HANDLER
// ============================================================

async function handleChat(
    event
) {

    event.preventDefault();


    if (!analysisContext) {

        appendChatMessage(
            "Please analyze a contract before asking security questions.",
            "bot"
        );

        return;

    }


    const question =
        chatInput.value.trim();


    if (!question) {

        return;

    }


    appendChatMessage(
        question,
        "user"
    );


    chatInput.value =
        "";


    const thinking =
        appendChatMessage(
            "Thinking...",
            "bot"
        );


    try {

        const answer =
            await getChatResponse(
                question,
                analysisContext
            );


        const content =
            thinking.querySelector(
                ".chat-content p"
            );


        if (content) {

    content.innerHTML =
        renderAssistantMarkdown(answer);
        
        }


    } catch (error) {

        console.error(
            "Chat request failed:",
            error
        );


        const content =
            thinking.querySelector(
                ".chat-content p"
            );


        if (content) {

            content.textContent =
                "Sorry, I couldn't generate a response right now.";

        }

    }

}


// ============================================================
// CHAT API REQUEST
// ============================================================

async function getChatResponse(
    question,
    context
) {

    const response =
        await fetch(
            `${API_BASE_URL}/chat`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    question:
                        question,

                    context:
                        context

                })

            }
        );


    let data = null;


    try {

        data =
            await response.json();

    } catch (error) {

        throw new Error(
            "The chatbot returned an invalid response."
        );

    }


    if (!response.ok) {

        throw new Error(
            data.error ||
            `Chat failed with HTTP ${response.status}.`
        );

    }


    return data.answer ||
        "No response was returned.";

}


// ============================================================
// CHAT MESSAGE
// ============================================================
// ============================================================
// AI ASSISTANT MARKDOWN RENDERER
// ============================================================

function renderAssistantMarkdown(markdown) {

    if (!markdown) {
        return "";
    }

    let text = String(markdown);

    // --------------------------------------------------------
    // Escape HTML for safety
    // --------------------------------------------------------

    text = escapeHTML(text);

    // --------------------------------------------------------
    // Headings
    // --------------------------------------------------------

    text = text.replace(
        /^### (.+)$/gm,
        "<h4>$1</h4>"
    );

    text = text.replace(
        /^## (.+)$/gm,
        "<h3>$1</h3>"
    );

    text = text.replace(
        /^# (.+)$/gm,
        "<h2>$1</h2>"
    );

    // --------------------------------------------------------
    // Bold
    // --------------------------------------------------------

    text = text.replace(
        /\*\*(.+?)\*\*/g,
        "<strong>$1</strong>"
    );

    // --------------------------------------------------------
    // Italic
    // --------------------------------------------------------

    text = text.replace(
        /\*([^*\n]+)\*/g,
        "<em>$1</em>"
    );

    // --------------------------------------------------------
    // Inline code
    // --------------------------------------------------------

    text = text.replace(
        /`([^`\n]+)`/g,
        "<code>$1</code>"
    );

    // --------------------------------------------------------
    // Bullet lists
    // --------------------------------------------------------

    text = text.replace(
        /^\s*[-*]\s+(.+)$/gm,
        "<li>$1</li>"
    );

    text = text.replace(
        /(<li>.*<\/li>\s*)+/g,
        "<ul>$&</ul>"
    );

    // --------------------------------------------------------
    // Numbered lists
    // --------------------------------------------------------

    text = text.replace(
        /^\s*\d+\.\s+(.+)$/gm,
        "<li>$1</li>"
    );

    // --------------------------------------------------------
    // Markdown tables
    // --------------------------------------------------------

    const lines =
        text.split("\n");

    const output = [];

    let i = 0;

    while (i < lines.length) {

        const line =
            lines[i];

        const nextLine =
            lines[i + 1] || "";

        // Detect table header + separator
        if (
            line.includes("|") &&
            nextLine.includes("|") &&
            /^[-|:\s]+$/.test(
                nextLine
            )
        ) {

            const headers =
                line
                    .split("|")
                    .map(
                        cell =>
                            cell.trim()
                    )
                    .filter(
                        cell =>
                            cell !== ""
                    );

            i += 2;

            const rows = [];

            while (
                i < lines.length &&
                lines[i].includes("|")
            ) {

                const row =
                    lines[i]
                        .split("|")
                        .map(
                            cell =>
                                cell.trim()
                        )
                        .filter(
                            cell =>
                                cell !== ""
                        );

                rows.push(row);

                i++;
            }

            let table =
                '<div class="ai-table-wrapper">' +
                '<table class="ai-response-table">' +
                "<thead><tr>";

            headers.forEach(
                function (header) {

                    table +=
                        `<th>${header}</th>`;
                }
            );

            table +=
                "</tr></thead><tbody>";

            rows.forEach(
                function (row) {

                    table +=
                        "<tr>";

                    row.forEach(
                        function (cell) {

                            table +=
                                `<td>${cell}</td>`;
                        }
                    );

                    table +=
                        "</tr>";
                }
            );

            table +=
                "</tbody></table></div>";

            output.push(table);

            continue;
        }

        output.push(line);

        i++;
    }

    text =
        output.join("\n");

    // --------------------------------------------------------
    // Horizontal lines
    // --------------------------------------------------------

    text = text.replace(
        /^-{3,}$/gm,
        "<hr>"
    );

    // --------------------------------------------------------
    // Paragraphs / line breaks
    // --------------------------------------------------------

    text = text.replace(
        /\n{2,}/g,
        "</p><p>"
    );

    text = text.replace(
        /\n/g,
        "<br>"
    );

    // --------------------------------------------------------
    // Return formatted HTML
    // --------------------------------------------------------

    return text;
}
function appendChatMessage(
    text,
    sender
) {

    const message =
        document.createElement(
            "div"
        );


    message.className =
        `chat-message ${sender}`;


    const avatar =
        sender === "user"
            ? "YOU"
            : "AI";


    const senderName =
        sender === "user"
            ? "You"
            : "TrustGuard AI";


    message.innerHTML =
        `
        <div class="chat-avatar">

            ${avatar}

        </div>


        <div class="chat-content">

            <strong>
                ${senderName}
            </strong>


            <p>
                ${escapeHTML(
                    String(text)
                )}
            </p>

        </div>
        `;


    chatBox.appendChild(
        message
    );


    chatBox.scrollTop =
        chatBox.scrollHeight;


    return message;

}


// ============================================================
// RESET CHAT
// ============================================================

function resetChat() {

    chatBox.innerHTML =
        `
        <div class="chat-message bot">

            <div class="chat-avatar">
                AI
            </div>


            <div class="chat-content">

                <strong>
                    TrustGuard AI
                </strong>


                <p>

                    Analysis complete! Ask me anything
                    about this contract's security findings.

                </p>

            </div>

        </div>
        `;

}


// ============================================================
// GENERIC LIST RENDERER
// ============================================================

function displayList(
    element,
    items,
    emptyMessage
) {

    element.innerHTML =
        "";


    if (
        !Array.isArray(items) ||
        items.length === 0
    ) {

        const li =
            document.createElement(
                "li"
            );


        li.textContent =
            emptyMessage;


        element.appendChild(
            li
        );


        return;

    }


    items.forEach(
        function (item) {

            const li =
                document.createElement(
                    "li"
                );


            if (
                typeof item === "object"
            ) {

                li.textContent =
                    item.vulnerability
                        ? `${item.vulnerability} | ${item.severity || ""}`
                        : JSON.stringify(
                            item
                        );

            } else {

                li.textContent =
                    String(item);

            }


            element.appendChild(
                li
            );

        }
    );

}


// ============================================================
// RISK COLOR
// ============================================================

function getRiskColor(
    risk
) {

    const value =
        String(
            risk ||
            ""
        ).toLowerCase();


    if (
        value.includes("very high") ||
        value.includes("critical")
    ) {

        return "#e74c3c";

    }


    if (
        value.includes("high")
    ) {

        return "#e67e22";

    }


    if (
        value.includes("medium") ||
        value.includes("conditional")
    ) {

        return "#f1c40f";

    }


    if (
        value.includes("low") ||
        value.includes("ready")
    ) {

        return "#2ecc71";

    }


    return "#8d99aa";

}


// ============================================================
// READINESS CLASS
// ============================================================

function getReadinessClass(
    status
) {

    const value =
        String(
            status ||
            ""
        ).toLowerCase();


    if (
        value.includes("ready") &&
        !value.includes("not")
    ) {

        return "ready";

    }


    if (
        value.includes("conditional")
    ) {

        return "conditional";

    }


    return "not-ready";

}


// ============================================================
// SEVERITY CLASS
// ============================================================

function getSeverityClass(
    severity
) {

    const value =
        String(
            severity ||
            "INFO"
        ).toLowerCase();


    if (
        value === "critical"
    ) {

        return "severity-critical";

    }


    if (
        value === "high"
    ) {

        return "severity-high";

    }


    if (
        value === "medium"
    ) {

        return "severity-medium";

    }


    if (
        value === "low"
    ) {

        return "severity-low";

    }


    return "severity-info";

}


// ============================================================
// FORMAT VULNERABILITY NAME
// ============================================================

function formatName(
    value
) {

    return String(value)
        .replace(
            /_/g,
            " "
        )
        .replace(
            /\s+/g,
            " "
        )
        .trim();

}


// ============================================================
// FORMAT PERCENTAGE
// ============================================================

function formatPercentage(
    value
) {

    if (
        value === undefined ||
        value === null
    ) {

        return "N/A";

    }


    const number =
        Number(value);


    if (
        Number.isNaN(number)
    ) {

        return "N/A";

    }


    const percentage =
        number <= 1
            ? number * 100
            : number;


    return (
        `${percentage.toFixed(2)}%`
    );

}


// ============================================================
// FORMAT LARGE NUMBERS
// ============================================================

function formatNumber(
    value
) {

    const number =
        Number(value);


    if (
        Number.isNaN(number)
    ) {

        return String(value);

    }


    return number.toLocaleString(
        "en-US"
    );

}


// ============================================================
// HTML ESCAPING
// ============================================================

function escapeHTML(
    value
) {

    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}


// ============================================================
// SHOW ERROR
// ============================================================

function showError(
    message
) {

    errorMessage.textContent =
        message;


    errorBox.classList.remove(
        "hidden"
    );

}


// ============================================================
// HIDE ERROR
// ============================================================

function hideError() {

    errorBox.classList.add(
        "hidden"
    );


    errorMessage.textContent =
        "";

}








