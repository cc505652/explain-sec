/**
 * ======================================================================
 * EXPLAINSEC ENTERPRISE VERIFICATION FRAMEWORK — FIRESTORE MOCKS
 * ======================================================================
 * Mock Firestore storage for offline unit testing without live network calls.
 * ======================================================================
 */

export class MockFirestore {
  constructor() {
    this.collections = new Map();
  }

  clear() {
    this.collections.clear();
  }

  collection(name) {
    if (!this.collections.has(name)) {
      this.collections.set(name, new Map());
    }
    return this.collections.get(name);
  }

  addDoc(collName, data) {
    const coll = this.collection(collName);
    const id = `mock_doc_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const docObj = { id, ...data, createdAt: new Date() };
    coll.set(id, docObj);
    return Promise.resolve({ id });
  }

  getDoc(collName, id) {
    const coll = this.collection(collName);
    const data = coll.get(id);
    return Promise.resolve({
      exists: () => !!data,
      data: () => data,
      id
    });
  }
}

export const mockFirestore = new MockFirestore();
