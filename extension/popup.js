document.addEventListener('DOMContentLoaded', () => {

    // ========================================================
    // DOM ELEMENTS
    // ========================================================

    const analyzeBtn =
        document.getElementById('analyzeBtn');

    const addressInput =
        document.getElementById('contractAddress');

    const loadingSpinner =
        document.getElementById('loader');

    const resultsDiv =
        document.getElementById('results');

    const scoreText =
        document.querySelector('.score-text');

    const riskLevelText =
        document.getElementById('riskLevel');

    const scoreCircle =
        document.querySelector('.progress-ring__circle');

    const flagsList =
        document.getElementById('flagsList');

    const readinessStatus =
        document.getElementById('readinessStatus');

    const readinessScore =
        document.getElementById('readinessScore');

    const readinessRisk =
        document.getElementById('readinessRisk');

    const blockingIssues =
        document.getElementById('blockingIssues');

    const readinessRecommendations =
        document.getElementById(
            'readinessRecommendations'
        );

    const vulnerabilitiesList =
        document.getElementById(
            'vulnerabilitiesList'
        );

    const repairsList =
        document.getElementById(
            'repairsList'
        );

    const onchainDetails =
        document.getElementById(
            'onchainDetails'
        );

    const chatSection =
        document.getElementById(
            'chatbot-container'
        );

    const chatBox =
        document.getElementById(
            'chat-box'
        );

    const chatInput =
        document.getElementById(
            'chat-input'
        );

    const chatForm =
        document.getElementById(
            'chat-input-form'
        );


    // ========================================================
    // API CONFIGURATION
    // ========================================================

    const API_BASE_URL =
        'http://127.0.0.1:5001';


    // Store latest analysis for chatbot.

    let analysisContext = null;


    // ========================================================
    // ANALYZE BUTTON
    // ========================================================

    if (analyzeBtn) {

        analyzeBtn.addEventListener(
            'click',
            async () => {

                const contractAddress =
                    addressInput.value.trim();

                if (
                    !/^0x[a-fA-F0-9]{40}$/
                        .test(contractAddress)
                ) {

                    alert(
                        'Please enter a valid Ethereum contract address.'
                    );

                    return;
                }


                // Show loading state.

                resultsDiv.classList.add(
                    'hidden'
                );

                chatSection.classList.add(
                    'hidden'
                );

                loadingSpinner.classList.remove(
                    'hidden'
                );

                analyzeBtn.disabled = true;


                try {

                    const result =
                        await analyzeContract(
                            contractAddress
                        );

                    analysisContext =
                        result;

                    displayResults(
                        result
                    );

                } catch (error) {

                    console.error(
                        'Analysis failed:',
                        error
                    );

                    alert(
                        `Analysis failed: ${error.message}`
                    );

                } finally {

                    loadingSpinner.classList.add(
                        'hidden'
                    );

                    analyzeBtn.disabled =
                        false;
                }
            }
        );

    } else {

        console.error(
            "Could not find 'analyzeBtn'."
        );
    }


    // ========================================================
    // CHAT
    // ========================================================

    if (chatForm) {

        chatForm.addEventListener(
            'submit',
            async (event) => {

                event.preventDefault();

                const userQuestion =
                    chatInput.value.trim();

                if (
                    !userQuestion ||
                    !analysisContext
                ) {
                    return;
                }


                appendMessage(
                    userQuestion,
                    'user'
                );

                chatInput.value = '';


                try {

                    const thinkingMessage =
                        appendMessage(
                            'Thinking...',
                            'bot'
                        );

                    const botAnswer =
                        await getChatResponse(
                            userQuestion,
                            analysisContext
                        );

                    thinkingMessage.textContent =
                        botAnswer;

                } catch (error) {

                    console.error(
                        'Chatbot request failed:',
                        error
                    );

                    appendMessage(
                        'Sorry, I am having trouble responding right now.',
                        'bot'
                    );
                }
            }
        );

    } else {

        console.error(
            "Could not find 'chat-input-form'."
        );
    }


    // ========================================================
    // ANALYZE API
    // ========================================================

    async function analyzeContract(address) {

        const response =
            await fetch(
                `${API_BASE_URL}/analyze`,
                {
                    method: 'POST',

                    headers: {
                        'Content-Type':
                            'application/json'
                    },

                    body: JSON.stringify({
                        contract_address:
                            address
                    })
                }
            );


        if (!response.ok) {

            let errorMessage =
                'Analysis request failed.';

            try {

                const errorData =
                    await response.json();

                errorMessage =
                    errorData.error ||
                    errorMessage;

            } catch (_) {
                // Ignore invalid JSON.
            }

            throw new Error(
                errorMessage
            );
        }


        return response.json();
    }


    // ========================================================
    // CHAT API
    // ========================================================

    async function getChatResponse(
        question,
        context
    ) {

        const response =
            await fetch(
                `${API_BASE_URL}/chat`,
                {
                    method: 'POST',

                    headers: {
                        'Content-Type':
                            'application/json'
                    },

                    body: JSON.stringify({
                        question: question,
                        context: context
                    })
                }
            );


        if (!response.ok) {

            let errorMessage =
                'Chatbot request failed.';

            try {

                const errorData =
                    await response.json();

                errorMessage =
                    errorData.error ||
                    errorMessage;

            } catch (_) {
                // Ignore invalid JSON.
            }

            throw new Error(
                errorMessage
            );
        }


        const data =
            await response.json();

        return data.answer;
    }


    // ========================================================
    // DISPLAY COMPLETE RESULTS
    // ========================================================

    function displayResults(data) {

        // ----------------------------------------------------
        // Risk score
        // ----------------------------------------------------

        const score =
            Number(data.score || 0);

        scoreText.textContent =
            `${score}/20`;

        riskLevelText.textContent =
            data.risk_level ||
            'Unknown';


        const circumference =
            2 * Math.PI * 50;

        const normalizedScore =
            Math.max(
                0,
                Math.min(
                    score / 20,
                    1
                )
            );

        const offset =
            circumference -
            normalizedScore *
            circumference;


        scoreCircle.style.strokeDasharray =
            `${circumference} ${circumference}`;

        scoreCircle.style.strokeDashoffset =
            offset;

        scoreCircle.style.stroke =
            getRiskColor(score);


        // ----------------------------------------------------
        // Red flags
        // ----------------------------------------------------

        renderFlags(
            data.flags || []
        );


        // ----------------------------------------------------
        // Deployment readiness
        // ----------------------------------------------------

        renderReadiness(
            data.deployment_readiness
        );


        // ----------------------------------------------------
        // Prioritized vulnerabilities
        // ----------------------------------------------------

        renderVulnerabilities(
            data.prioritized_vulnerabilities ||
            []
        );


        // ----------------------------------------------------
        // Repair suggestions
        // ----------------------------------------------------

        renderRepairs(
            data.repair_suggestions ||
            []
        );


        // ----------------------------------------------------
        // On-chain information
        // ----------------------------------------------------

        renderOnchain(
            data.onchain,
            data.liquidity
        );


        // ----------------------------------------------------
        // Show result sections
        // ----------------------------------------------------

        resultsDiv.classList.remove(
            'hidden'
        );

        chatSection.classList.remove(
            'hidden'
        );
    }


    // ========================================================
    // RED FLAGS
    // ========================================================

    function renderFlags(flags) {

        flagsList.innerHTML = '';


        if (!flags.length) {

            const li =
                document.createElement(
                    'li'
                );

            li.textContent =
                'No specific red flags were detected.';

            flagsList.appendChild(li);

            return;
        }


        flags.forEach(flag => {

            const li =
                document.createElement(
                    'li'
                );

            const name =
                String(
                    flag.name ||
                    'Unknown'
                ).replace(
                    /_/g,
                    ' '
                );


            li.innerHTML =
                `<strong>${escapeHtml(name)}:</strong> ` +
                `${escapeHtml(flag.description || '')}`;


            flagsList.appendChild(li);
        });
    }


    // ========================================================
    // DEPLOYMENT READINESS
    // ========================================================

    function renderReadiness(
        readiness
    ) {

        if (!readiness) {

            readinessStatus.textContent =
                'Unavailable';

            readinessScore.textContent =
                '-';

            readinessRisk.textContent =
                '-';

            return;
        }


        readinessStatus.textContent =
            readiness.status ||
            'Unknown';


        readinessScore.textContent =
            `${readiness.readiness_score ?? 0}/100`;


        readinessRisk.textContent =
            readiness.risk_level ||
            'Unknown';


        readinessStatus.className =
            'readiness-status ' +
            getReadinessClass(
                readiness.status
            );


        // ----------------------------------------------------
        // Blocking issues
        // ----------------------------------------------------

        blockingIssues.innerHTML = '';


        const blockers =
            readiness.blocking_issues ||
            [];


        if (!blockers.length) {

            const li =
                document.createElement(
                    'li'
                );

            li.textContent =
                'No blocking issues detected.';

            blockingIssues.appendChild(
                li
            );

        } else {

            blockers.forEach(issue => {

                const li =
                    document.createElement(
                        'li'
                    );


                if (
                    typeof issue ===
                    'object'
                ) {

                    li.textContent =
                        `${issue.vulnerability || 'Unknown'} | ` +
                        `${issue.severity || 'UNKNOWN'}`;

                } else {

                    li.textContent =
                        issue;
                }


                blockingIssues.appendChild(
                    li
                );
            });
        }


        // ----------------------------------------------------
        // Recommendations
        // ----------------------------------------------------

        readinessRecommendations.innerHTML =
            '';


        const recommendations =
            readiness.recommendations ||
            [];


        recommendations.forEach(
            recommendation => {

                const li =
                    document.createElement(
                        'li'
                    );

                li.textContent =
                    recommendation;

                readinessRecommendations
                    .appendChild(li);
            }
        );
    }


    // ========================================================
    // VULNERABILITIES
    // ========================================================

    function renderVulnerabilities(
        vulnerabilities
    ) {

        vulnerabilitiesList.innerHTML =
            '';


        if (!vulnerabilities.length) {

            const empty =
                document.createElement(
                    'p'
                );

            empty.textContent =
                'No prioritized vulnerabilities detected.';

            vulnerabilitiesList.appendChild(
                empty
            );

            return;
        }


        vulnerabilities.forEach(
            vulnerability => {

                const card =
                    document.createElement(
                        'div'
                    );

                card.className =
                    'vulnerability-card';


                card.innerHTML = `
                    <div class="finding-header">
                        <strong>
                            Priority ${escapeHtml(
                                vulnerability.priority
                            )}
                        </strong>

                        <span class="severity-badge">
                            ${escapeHtml(
                                vulnerability.severity ||
                                'INFO'
                            )}
                        </span>
                    </div>

                    <h3>
                        ${escapeHtml(
                            vulnerability.vulnerability ||
                            'Unknown vulnerability'
                        )}
                    </h3>

                    <p>
                        Probability:
                        ${formatProbability(
                            vulnerability.probability
                        )}
                    </p>

                    <p>
                        Severity Score:
                        ${escapeHtml(
                            vulnerability.severity_score ??
                            '-'
                        )}
                    </p>

                    <p>
                        Priority Score:
                        ${escapeHtml(
                            vulnerability.priority_score ??
                            '-'
                        )}
                    </p>

                    <p>
                        Source:
                        ${escapeHtml(
                            vulnerability.source ||
                            'UNKNOWN'
                        )}
                    </p>
                `;


                vulnerabilitiesList.appendChild(
                    card
                );
            }
        );
    }


    // ========================================================
    // REPAIR SUGGESTIONS
    // ========================================================

    function renderRepairs(
        repairs
    ) {

        repairsList.innerHTML =
            '';


        if (!repairs.length) {

            const empty =
                document.createElement(
                    'p'
                );

            empty.textContent =
                'No repair suggestions available.';

            repairsList.appendChild(
                empty
            );

            return;
        }


        repairs.forEach(
            repair => {

                const card =
                    document.createElement(
                        'div'
                    );

                card.className =
                    'repair-card';


                card.innerHTML = `
                    <div class="finding-header">
                        <strong>
                            Priority ${escapeHtml(
                                repair.priority
                            )}
                        </strong>

                        <span>
                            ${repair.ai_ready ? 'AI Ready' : 'Manual Review'}
                        </span>
                    </div>

                    <h3>
                        ${escapeHtml(
                            repair.title ||
                            repair.vulnerability ||
                            'Repair Suggestion'
                        )}
                    </h3>

                    <p>
                        <strong>Problem:</strong>
                        ${escapeHtml(
                            repair.problem ||
                            'No problem description available.'
                        )}
                    </p>

                    <p>
                        <strong>Recommendation:</strong>
                        ${escapeHtml(
                            repair.recommendation ||
                            'Manual security review required.'
                        )}
                    </p>
                `;


                if (
                    repair.secure_pattern
                ) {

                    const pre =
                        document.createElement(
                            'pre'
                        );

                    pre.className =
                        'secure-pattern';

                    pre.textContent =
                        repair.secure_pattern;

                    card.appendChild(
                        pre
                    );
                }


                repairsList.appendChild(
                    card
                );
            }
        );
    }


    // ========================================================
    // ON-CHAIN DATA
    // ========================================================

    function renderOnchain(
        onchain,
        liquidity
    ) {

        onchainDetails.innerHTML =
            '';


        if (!onchain && !liquidity) {

            onchainDetails.textContent =
                'On-chain information unavailable.';

            return;
        }


        if (onchain) {

            const supply =
                document.createElement(
                    'p'
                );

            supply.innerHTML =
                `<strong>Total Supply:</strong> ` +
                `${escapeHtml(
                    onchain.total_supply ??
                    '-'
                )}`;

            onchainDetails.appendChild(
                supply
            );


            const decimals =
                document.createElement(
                    'p'
                );

            decimals.innerHTML =
                `<strong>Decimals:</strong> ` +
                `${escapeHtml(
                    onchain.decimals ??
                    '-'
                )}`;

            onchainDetails.appendChild(
                decimals
            );
        }


        if (liquidity) {

            const pool =
                document.createElement(
                    'p'
                );

            pool.innerHTML =
                `<strong>Liquidity Pool:</strong> ` +
                `${liquidity.pool_exists ? 'Found' : 'Not Found'}`;

            onchainDetails.appendChild(
                pool
            );


            const burn =
                document.createElement(
                    'p'
                );

            burn.innerHTML =
                `<strong>LP Burn Percentage:</strong> ` +
                `${Number(
                    liquidity.burn_percentage || 0
                ).toFixed(4)}%`;

            onchainDetails.appendChild(
                burn
            );
        }
    }


    // ========================================================
    // CHAT MESSAGE
    // ========================================================

    function appendMessage(
        text,
        sender
    ) {

        const messageDiv =
            document.createElement(
                'div'
            );


        if (sender === 'bot') {

            messageDiv.classList.add(
                'bot-message'
            );

        } else {

            messageDiv.classList.add(
                'user-message'
            );
        }


        const paragraph =
            document.createElement(
                'p'
            );

        paragraph.textContent =
            text;


        messageDiv.appendChild(
            paragraph
        );

        chatBox.appendChild(
            messageDiv
        );

        chatBox.scrollTop =
            chatBox.scrollHeight;


        return paragraph;
    }


    // ========================================================
    // RISK COLOR
    // ========================================================

    function getRiskColor(
        score
    ) {

        if (score >= 18) {
            return '#2ecc71';
        }

        if (score >= 15) {
            return '#f1c40f';
        }

        if (score >= 10) {
            return '#e67e22';
        }

        return '#e74c3c';
    }


    // ========================================================
    // READINESS CSS CLASS
    // ========================================================

    function getReadinessClass(
        status
    ) {

        const normalized =
            String(
                status || ''
            ).toUpperCase();


        if (
            normalized === 'READY'
        ) {

            return 'ready';
        }


        if (
            normalized ===
                'CONDITIONAL'
        ) {

            return 'conditional';
        }


        return 'not-ready';
    }


    // ========================================================
    // PROBABILITY FORMAT
    // ========================================================

    function formatProbability(
        probability
    ) {

        const value =
            Number(
                probability
            );


        if (
            Number.isNaN(value)
        ) {

            return '-';
        }


        return `${(
            value * 100
        ).toFixed(2)}%`;
    }


    // ========================================================
    // BASIC HTML ESCAPING
    // ========================================================

    function escapeHtml(
        value
    ) {

        const div =
            document.createElement(
                'div'
            );

        div.textContent =
            String(
                value ??
                ''
            );

        return div.innerHTML;
    }

});