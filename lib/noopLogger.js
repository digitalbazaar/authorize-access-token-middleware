/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
export default new Proxy({}, {
  get() {
    return () => {};
  }
});