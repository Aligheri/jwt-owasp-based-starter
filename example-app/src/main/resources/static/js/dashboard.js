document.addEventListener('DOMContentLoaded', () => {
    console.log("Dashboard page loaded");

    // Check authentication first
    if (!isAuthenticated()) {
        console.log("Not authenticated, redirecting to login");
        window.location.href = '/login';
        return;
    }

    const token = getToken();
    console.log("Token found, loading dashboard data");

    // Fetch protected dashboard content
    authenticatedFetch('/dashboard/data')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            console.log("Dashboard data loaded successfully:", data);
            // Render dashboard content
            const dashboardContent = document.getElementById('dashboard-content');
            if (dashboardContent) {
                dashboardContent.innerHTML = `
                    <h2>Welcome to Dashboard</h2>
                    <p>User: ${data.username || 'Unknown'}</p>
                    <p>Email: ${data.email || 'Not provided'}</p>
                    <button onclick="logout().then(() => window.location.href = '/login')">Logout</button>
                `;
            } else {
                console.error("Dashboard content element not found");
            }
        })
        .catch(error => {
            console.error('Dashboard error:', error);

            // Check if it's an authentication error
            if (error.message.includes('Authentication') || error.message.includes('401')) {
                console.log("Authentication error, redirecting to login");
                removeToken();
                window.location.href = '/login';
            } else {
                // Show error message on dashboard
                const dashboardContent = document.getElementById('dashboard-content');
                if (dashboardContent) {
                    dashboardContent.innerHTML = `
                        <div class="error-message">
                            <h2>Error Loading Dashboard</h2>
                            <p>${error.message}</p>
                            <button onclick="window.location.reload()">Retry</button>
                            <button onclick="logout().then(() => window.location.href = '/login')">Logout</button>
                        </div>
                    `;
                }
            }
        });
});