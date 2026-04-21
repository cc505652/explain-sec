// Authentication helper functions for Playwright tests

/**
 * Login to the SOC platform
 * @param {Page} page - Playwright page object
 * @param {string} email - User email
 * @param {string} password - User password
 * @param {string} expectedRoute - Expected route after login (optional)
 */
export async function login(page, email, password, expectedRoute = '/') {
  console.log(`TEST STEP: Logging in as ${email}`);
  
  // Navigate to login page - use domcontentloaded to avoid Firebase WebSocket hangs
  await page.goto('/', { waitUntil: 'domcontentloaded' });
  // Brief pause to let React mount after domcontentloaded
  await page.waitForTimeout(500);
  
  // Wait for login form to be visible
  await page.waitForSelector('input[type="email"]', { timeout: 10000 });
  
  // Fill in credentials - try data-testid first, fallback to type selector
  try {
    await page.fill('[data-testid="email-input"]', email);
  } catch {
    await page.fill('input[type="email"]', email);
  }
  try {
    await page.fill('[data-testid="password-input"]', password);
  } catch {
    await page.fill('input[type="password"]', password);
  }
  
  // Submit login form - try data-testid first, fallback to type selector
  try {
    await page.click('[data-testid="login-button"]');
  } catch {
    await page.click('button[type="submit"]');
  }
  
  // Wait for navigation to complete - use domcontentloaded to avoid Firebase WebSocket hangs
  await page.waitForURL(expectedRoute, { timeout: 30000, waitUntil: 'domcontentloaded' });
  
  // Wait for dashboard to load - use domcontentloaded instead of networkidle for React apps
  await page.waitForLoadState('domcontentloaded');
  
  console.log(`TEST STEP: Successfully logged in as ${email}, redirected to ${expectedRoute}`);
}

/**
 * Logout from the SOC platform
 * @param {Page} page - Playwright page object
 */
export async function logout(page) {
  console.log('TEST STEP: Logging out');
  
  // Click logout button (assuming there's a logout button)
  // This will need to be adjusted based on actual UI
  const logoutButton = await page.locator('text=Logout').or(page.locator('[data-testid="logout-button"]'));
  
  if (await logoutButton.isVisible()) {
    await logoutButton.click();
    console.log('TEST STEP: Successfully logged out');
  } else {
    console.log('TEST STEP: No logout button found, skipping logout');
  }
}

/**
 * Quick login using role-based credentials
 * @param {Page} page - Playwright page object
 * @param {string} role - Role to login as (soc_l1, soc_l2, soc_manager, ir, admin)
 */
export async function quickLogin(page, role) {
  const credentials = {
    soc_l1: { email: 'analyst@explainsec.com', password: 'test1234', route: '/' },
    soc_l2: { email: 'analyst1@explainsec.com', password: 'test1234', route: '/' },
    soc_manager: { email: 'cc505652@gmail.com', password: 'test1234', route: '/soc-manager' },
    ir: { email: 'ir_team@explainsec.com', password: 'test1234', route: '/' },
    admin: { email: 'admin@explainsec.com', password: 'test1234', route: '/admin' },
  };
  
  const creds = credentials[role];
  if (!creds) {
    throw new Error(`Unknown role: ${role}`);
  }
  
  await login(page, creds.email, creds.password, creds.route);
}

/**
 * Wait for authentication state to be ready
 * @param {Page} page - Playwright page object
 */
export async function waitForAuth(page) {
  console.log('TEST STEP: Waiting for authentication to be ready');
  
  // Wait for either login form or dashboard to be visible
  await Promise.race([
    page.waitForSelector('input[type="email"]'),
    page.waitForSelector('[data-testid="dashboard"]'),
  ]);
  
  console.log('TEST STEP: Authentication state ready');
}
