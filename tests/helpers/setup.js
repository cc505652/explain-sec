// Setup helper functions for test data seeding

/**
 * Seed test users in Firebase
 * This function would typically call Firebase SDK to create test users
 * For now, it's a placeholder that documents the test users
 */
export const TEST_USERS = {
  soc_l1: {
    email: 'analyst@explainsec.com',
    password: 'test1234',
    role: 'soc_l1',
    team: 'soc_l1',
    name: 'SOC L1 Analyst'
  },
  soc_l2: {
    email: 'analyst1@explainsec.com',
    password: 'test1234',
    role: 'soc_l2',
    team: 'soc_l2',
    name: 'SOC L2 Analyst'
  },
  soc_manager: {
    email: 'cc505652@gmail.com',
    password: 'test1234',
    role: 'soc_manager',
    team: 'soc_manager',
    name: 'SOC Manager'
  },
  ir: {
    email: 'ir_team@explainsec.com',
    password: 'test1234',
    role: 'ir',
    team: 'ir',
    name: 'Incident Response'
  },
  admin: {
    email: 'admin@explainsec.com',
    password: 'test1234',
    role: 'admin',
    team: 'admin',
    name: 'Administrator'
  },
  threat_hunter: {
    email: 'threat_hunter@explainsec.com',
    password: 'test1234',
    role: 'threat_hunter',
    team: 'threat_hunter',
    name: 'Threat Hunter'
  },
  student: {
    email: 'student@explainsec.com',
    password: 'test1234',
    role: 'student',
    team: 'student',
    name: 'Student'
  }
};

/**
 * Seed test incidents in Firestore
 * This function would typically call Firestore SDK to create test incidents
 */
export const TEST_INCIDENTS = {
  open: {
    status: 'open',
    title: 'Test Open Incident',
    description: 'This is a test incident in open state',
    urgency: 'medium',
    assignedTo: 'soc_l1',
    visibleTo: ['soc_l1', 'soc_l2', 'soc_manager']
  },
  in_progress: {
    status: 'in_progress',
    title: 'Test In Progress Incident',
    description: 'This is a test incident in in_progress state',
    urgency: 'high',
    assignedTo: 'soc_l1',
    visibleTo: ['soc_l1', 'soc_l2', 'soc_manager']
  },
  confirmed_threat: {
    status: 'confirmed_threat',
    title: 'Test Confirmed Threat',
    description: 'This is a test incident in confirmed_threat state',
    urgency: 'critical',
    assignedTo: 'soc_l2',
    visibleTo: ['soc_l2', 'soc_manager']
  },
  escalation_pending: {
    status: 'escalation_pending',
    title: 'Test Escalation Pending',
    description: 'This is a test incident in escalation_pending state',
    urgency: 'critical',
    assignedTo: 'soc_l2',
    escalatedTo: 'soc_manager',
    escalationRequested: true,
    visibleTo: ['soc_l2', 'soc_manager']
  },
  escalation_approved: {
    status: 'escalation_approved',
    title: 'Test Escalation Approved',
    description: 'This is a test incident in escalation_approved state',
    urgency: 'critical',
    assignedTo: 'ir',
    escalatedTo: 'ir',
    escalationApproved: true,
    visibleTo: ['soc_l2', 'soc_manager', 'ir']
  },
  containment_pending_approval: {
    status: 'containment_pending_approval',
    title: 'Test Containment Pending Approval',
    description: 'This is a test incident in containment_pending_approval state',
    urgency: 'critical',
    assignedTo: 'soc_l2',
    containmentRequested: true,
    visibleTo: ['soc_l2', 'soc_manager']
  },
  containment_action_submitted: {
    status: 'containment_action_submitted',
    title: 'Test Containment Action Submitted',
    description: 'This is a test incident in containment_action_submitted state',
    urgency: 'critical',
    assignedTo: 'ir',
    irAction: {
      type: 'block_ip',
      details: 'Block malicious IP'
    },
    visibleTo: ['soc_l2', 'soc_manager', 'ir']
  },
  containment_completed: {
    status: 'containment_completed',
    title: 'Test Containment Completed',
    description: 'This is a test incident in containment_completed state',
    urgency: 'critical',
    assignedTo: 'soc_l2',
    visibleTo: ['soc_l2', 'soc_manager']
  },
  resolved: {
    status: 'resolved',
    title: 'Test Resolved Incident',
    description: 'This is a test incident in resolved state',
    urgency: 'low',
    assignedTo: 'soc_l2',
    visibleTo: ['soc_l1', 'soc_l2', 'soc_manager', 'ir']
  }
};

/**
 * Cleanup test data after tests
 * This would delete test users and incidents from Firebase
 */
export async function cleanupTestData() {
  console.log('TEST SETUP: Cleaning up test data');
  // Implementation would call Firebase SDK to delete test data
}

/**
 * Setup test data before tests
 * This would create test users and incidents in Firebase
 */
export async function setupTestData() {
  console.log('TEST SETUP: Setting up test data');
  // Implementation would call Firebase SDK to create test data
}
