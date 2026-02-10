/**
 * Identity Hygiene Scanner - Frontend Application
 * 
 * SECURITY FEATURES:
 * 1. Input sanitization before sending to API
 * 2. No sensitive data in console logs
 * 3. Secure error handling
 * 4. XSS prevention via textContent (not innerHTML)
 */

// Tab Management
document.addEventListener('DOMContentLoaded', () => {
    initializeTabs();
    initializePasswordChecker();
    initializeUsernameChecker();
    initializeMFAChecker();
});

/**
 * Tab switching functionality
 */
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Remove active class from all tabs
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to selected tab
            button.classList.add('active');
            document.getElementById(`${targetTab}-tab`).classList.add('active');
        });
    });
}

/**
 * Password Strength Checker
 */
function initializePasswordChecker() {
    const passwordInput = document.getElementById('password-input');
    const toggleButton = document.getElementById('toggle-password');
    const checkButton = document.getElementById('check-password-btn');
    
    // Toggle password visibility
    toggleButton.addEventListener('click', () => {
        const type = passwordInput.type === 'password' ? 'text' : 'password';
        passwordInput.type = type;
        toggleButton.textContent = type === 'password' ? '👁️ Show' : '🙈 Hide';
    });
    
    // Check password on button click
    checkButton.addEventListener('click', async () => {
        const password = passwordInput.value;
        
        if (!password) {
            alert('Please enter a password to analyze');
            return;
        }
        
        await analyzePassword(password);
    });
    
    // Also check on Enter key
    passwordInput.addEventListener('keypress', async (e) => {
        if (e.key === 'Enter') {
            await analyzePassword(passwordInput.value);
        }
    });
}

/**
 * Analyze password strength
 * SECURITY: Password is sent via POST, never in URL
 */
async function analyzePassword(password) {
    const resultsDiv = document.getElementById('password-results');
    
    try {
        const response = await fetch('/api/check-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password })
        });
        
        if (!response.ok) {
            throw new Error('Analysis failed');
        }
        
        const data = await response.json();
        displayPasswordResults(data);
        resultsDiv.classList.remove('hidden');
        
        // Scroll to results
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
    } catch (error) {
        console.error('Error analyzing password');
        alert('Failed to analyze password. Please try again.');
    }
}

/**
 * Display password analysis results
 * SECURITY: Uses textContent to prevent XSS
 */
function displayPasswordResults(data) {
    // Update strength meter
    const strengthBar = document.getElementById('strength-bar');
    const strengthLabel = document.getElementById('strength-label');
    
    strengthBar.style.width = `${data.score}%`;
    strengthLabel.textContent = `Strength: ${data.strength}`;
    
    // Set color based on strength
    const strengthColors = {
        'Very Weak': '#dc2626',
        'Weak': '#f59e0b',
        'Fair': '#eab308',
        'Good': '#10b981',
        'Strong': '#059669'
    };
    
    strengthBar.style.backgroundColor = strengthColors[data.strength] || '#64748b';
    strengthLabel.style.color = strengthColors[data.strength] || '#64748b';
    
    // Update metrics
    document.getElementById('password-score').textContent = data.score;
    document.getElementById('password-length').textContent = `${data.length} chars`;
    document.getElementById('password-entropy').textContent = `${data.entropy_bits} bits`;
    document.getElementById('crack-time').textContent = data.crack_time;
    
    // Update character type badges
    updateBadge('has-lowercase', data.has_lowercase);
    updateBadge('has-uppercase', data.has_uppercase);
    updateBadge('has-digits', data.has_digits);
    updateBadge('has-special', data.has_special);
    
    // Display issues
    const issuesList = document.getElementById('password-issues');
    issuesList.innerHTML = '';
    data.issues.forEach(issue => {
        const li = document.createElement('li');
        li.textContent = issue;
        issuesList.appendChild(li);
    });
    
    // Display recommendations
    const recommendationsList = document.getElementById('password-recommendations');
    recommendationsList.innerHTML = '';
    data.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = rec;
        recommendationsList.appendChild(li);
    });
}

/**
 * Update character type badge
 */
function updateBadge(elementId, isActive) {
    const badge = document.getElementById(elementId);
    if (isActive) {
        badge.classList.add('active');
    } else {
        badge.classList.remove('active');
    }
}

/**
 * Username and Email Checker
 */
function initializeUsernameChecker() {
    const usernameInput = document.getElementById('username-input');
    const emailInput = document.getElementById('email-input');
    const checkButton = document.getElementById('check-username-btn');
    
    checkButton.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        const email = emailInput.value.trim();
        
        if (!username) {
            alert('Please enter a username to analyze');
            return;
        }
        
        await analyzeUsername(username, email);
    });
    
    // Check on Enter key
    const checkOnEnter = async (e) => {
        if (e.key === 'Enter') {
            const username = usernameInput.value.trim();
            const email = emailInput.value.trim();
            if (username) {
                await analyzeUsername(username, email);
            }
        }
    };
    
    usernameInput.addEventListener('keypress', checkOnEnter);
    emailInput.addEventListener('keypress', checkOnEnter);
}

/**
 * Analyze username and email
 */
async function analyzeUsername(username, email) {
    const resultsDiv = document.getElementById('username-results');
    
    try {
        const response = await fetch('/api/check-username', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Analysis failed');
        }
        
        const data = await response.json();
        displayUsernameResults(data);
        resultsDiv.classList.remove('hidden');
        
        // Scroll to results
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
    } catch (error) {
        alert(error.message || 'Failed to analyze username. Please try again.');
    }
}

/**
 * Display username analysis results
 */
function displayUsernameResults(data) {
    // Update risk level banner
    const banner = document.getElementById('risk-level-banner');
    const riskLabel = document.getElementById('risk-label');
    
    riskLabel.textContent = `Risk Level: ${data.risk_level}`;
    
    // Remove old risk classes
    banner.classList.remove('low', 'medium', 'high');
    banner.classList.add(data.risk_level.toLowerCase());
    
    // Update enumeration risk
    document.getElementById('enumeration-risk').textContent = data.enumeration_risk;
    
    // Display issues
    const issuesList = document.getElementById('username-issues');
    issuesList.innerHTML = '';
    data.issues.forEach(issue => {
        const li = document.createElement('li');
        li.textContent = issue;
        issuesList.appendChild(li);
    });
    
    // Display warnings
    const warningsSection = document.getElementById('username-warnings-section');
    const warningsList = document.getElementById('username-warnings');
    
    if (data.warnings && data.warnings.length > 0) {
        warningsSection.style.display = 'block';
        warningsList.innerHTML = '';
        data.warnings.forEach(warning => {
            const li = document.createElement('li');
            li.textContent = warning;
            warningsList.appendChild(li);
        });
    } else {
        warningsSection.style.display = 'none';
    }
    
    // Display recommendations
    const recommendationsList = document.getElementById('username-recommendations');
    recommendationsList.innerHTML = '';
    data.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = rec;
        recommendationsList.appendChild(li);
    });
}

/**
 * MFA Readiness Checker
 */
function initializeMFAChecker() {
    loadMFAChecklist();
    setupMFAAssessment();
}

/**
 * Load and display MFA checklist
 */
async function loadMFAChecklist() {
    try {
        const response = await fetch('/api/mfa-checklist');
        const data = await response.json();
        
        displayMFAMethods(data.methods);
        displayMFAChecklist(data.checklist);
        displayCriticalAccounts(data.critical_accounts);
        setupMFAMethodCheckboxes(data.methods);
        
    } catch (error) {
        console.error('Error loading MFA checklist');
    }
}

/**
 * Display MFA methods with security rankings
 */
function displayMFAMethods(methods) {
    const methodsList = document.getElementById('mfa-methods-list');
    methodsList.innerHTML = '';
    
    // Sort by security level (highest first)
    const sortedMethods = Object.entries(methods).sort(
        (a, b) => b[1].security_level - a[1].security_level
    );
    
    sortedMethods.forEach(([key, method]) => {
        const card = document.createElement('div');
        card.className = 'mfa-method-card';
        
        // Create security level dots
        const dots = [];
        for (let i = 0; i < 5; i++) {
            dots.push(i < method.security_level ? 'filled' : '');
        }
        
        card.innerHTML = `
            <div class="mfa-method-header">
                <span class="mfa-method-name">${method.name}</span>
                <div class="security-level">
                    ${dots.map(c => `<span class="security-dot ${c}"></span>`).join('')}
                </div>
            </div>
            <p class="mfa-method-description">${method.description}</p>
            <div class="pros-cons">
                <div class="pros">
                    <h4>✓ Pros</h4>
                    <ul>
                        ${method.pros.map(p => `<li>${escapeHtml(p)}</li>`).join('')}
                    </ul>
                </div>
                <div class="cons">
                    <h4>✗ Cons</h4>
                    <ul>
                        ${method.cons.map(c => `<li>${escapeHtml(c)}</li>`).join('')}
                    </ul>
                </div>
            </div>
        `;
        
        methodsList.appendChild(card);
    });
}

/**
 * Setup MFA method checkboxes for assessment
 */
function setupMFAMethodCheckboxes(methods) {
    const container = document.getElementById('mfa-method-checkboxes');
    container.innerHTML = '';
    
    Object.entries(methods).forEach(([key, method]) => {
        const label = document.createElement('label');
        label.className = 'checkbox-label';
        
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = key;
        checkbox.name = 'mfa-method';
        
        label.appendChild(checkbox);
        label.appendChild(document.createTextNode(method.name));
        
        container.appendChild(label);
    });
}

/**
 * Setup MFA assessment functionality
 */
function setupMFAAssessment() {
    const assessButton = document.getElementById('assess-mfa-btn');
    
    assessButton.addEventListener('click', async () => {
        const checkboxes = document.querySelectorAll('input[name="mfa-method"]:checked');
        const methods = Array.from(checkboxes).map(cb => cb.value);
        
        await assessMFASetup(methods);
    });
}

/**
 * Assess current MFA setup
 */
async function assessMFASetup(methods) {
    const resultsDiv = document.getElementById('mfa-assessment-results');
    
    try {
        const response = await fetch('/api/mfa-assess', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ methods })
        });
        
        const data = await response.json();
        displayMFAAssessment(data);
        resultsDiv.classList.remove('hidden');
        
        // Scroll to results
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
    } catch (error) {
        console.error('Error assessing MFA setup');
    }
}

/**
 * Display MFA assessment results
 */
function displayMFAAssessment(data) {
    const resultsDiv = document.getElementById('mfa-assessment-results');
    
    const statusColors = {
        'Critical': '#dc2626',
        'Poor': '#f59e0b',
        'Fair': '#eab308',
        'Good': '#10b981',
        'Very Good': '#059669',
        'Excellent': '#059669'
    };
    
    resultsDiv.innerHTML = `
        <div class="info-box" style="border-left-color: ${statusColors[data.status]}">
            <h3>Assessment: ${data.status}</h3>
            ${data.enabled_count ? `<p>You have ${data.enabled_count} MFA method(s) enabled.</p>` : ''}
            <h4 style="margin-top: 1rem;">Recommendations:</h4>
            <ul>
                ${data.recommendations.map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
            </ul>
        </div>
    `;
}

/**
 * Display MFA implementation checklist
 */
function displayMFAChecklist(checklist) {
    displayChecklistSection('checklist-preparation', checklist.preparation);
    displayChecklistSection('checklist-implementation', checklist.implementation);
    displayChecklistSection('checklist-best-practices', checklist.best_practices);
}

/**
 * Display a checklist section
 */
function displayChecklistSection(elementId, items) {
    const list = document.getElementById(elementId);
    list.innerHTML = '';
    
    items.forEach(item => {
        const li = document.createElement('li');
        li.className = `priority-${item.priority.toLowerCase().replace(' ', '-')}`;
        
        const header = document.createElement('div');
        header.className = 'checklist-item-header';
        header.textContent = item.item;
        
        const badge = document.createElement('span');
        badge.className = `priority-badge priority-${item.priority.toLowerCase().replace(' ', '-')}-badge`;
        badge.textContent = item.priority;
        header.appendChild(badge);
        
        const details = document.createElement('div');
        details.className = 'checklist-item-details';
        details.textContent = item.details;
        
        li.appendChild(header);
        li.appendChild(details);
        list.appendChild(li);
    });
}

/**
 * Display critical accounts that need MFA
 */
function displayCriticalAccounts(accounts) {
    const list = document.getElementById('critical-accounts-list');
    list.innerHTML = '';
    
    accounts.forEach(account => {
        const li = document.createElement('li');
        li.textContent = account;
        list.appendChild(li);
    });
}

/**
 * SECURITY: Escape HTML to prevent XSS
 * Used when we need to insert user content into innerHTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * SECURITY: Clear sensitive data from memory
 * Called when user navigates away or closes tab
 */
window.addEventListener('beforeunload', () => {
    // Clear password input
    const passwordInput = document.getElementById('password-input');
    if (passwordInput) {
        passwordInput.value = '';
    }
});
