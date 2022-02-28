/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/@dazn/lambda-powertools-correlation-ids/index.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@dazn/lambda-powertools-correlation-ids/index.js ***!
  \***********************************************************************/
/***/ ((module) => {

const DEBUG_LOG_ENABLED = 'debug-log-enabled'

class CorrelationIds {
  constructor (context = {}) {
    this.context = context
  }

  clearAll () {
    this.context = {}
  }

  replaceAllWith (ctx) {
    this.context = ctx
  }

  set (key, value) {
    if (!key.startsWith('x-correlation-')) {
      key = 'x-correlation-' + key
    }

    this.context[key] = value
  }

  get () {
    return this.context
  }

  get debugLoggingEnabled () {
    return this.context[DEBUG_LOG_ENABLED] === 'true'
  }

  set debugLoggingEnabled (enabled) {
    this.context[DEBUG_LOG_ENABLED] = enabled ? 'true' : 'false'
  }

  static clearAll () {
    globalCorrelationIds.clearAll()
  }

  static replaceAllWith (...args) {
    globalCorrelationIds.replaceAllWith(...args)
  }

  static set (...args) {
    globalCorrelationIds.set(...args)
  }

  static get () {
    return globalCorrelationIds.get()
  }

  static get debugLoggingEnabled () {
    return globalCorrelationIds.debugLoggingEnabled
  }

  static set debugLoggingEnabled (enabled) {
    globalCorrelationIds.debugLoggingEnabled = enabled
  }
}

if (!global.CORRELATION_IDS) {
  global.CORRELATION_IDS = new CorrelationIds()
}

const globalCorrelationIds = global.CORRELATION_IDS

module.exports = CorrelationIds


/***/ }),

/***/ "./node_modules/@dazn/lambda-powertools-logger/index.js":
/*!**************************************************************!*\
  !*** ./node_modules/@dazn/lambda-powertools-logger/index.js ***!
  \**************************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

const CorrelationIds = __webpack_require__(/*! @dazn/lambda-powertools-correlation-ids */ "./node_modules/@dazn/lambda-powertools-correlation-ids/index.js")

// Levels here are identical to bunyan practices
// https://github.com/trentm/node-bunyan#levels
const LogLevels = {
  DEBUG: 20,
  INFO: 30,
  WARN: 40,
  ERROR: 50
}

// most of these are available through the Node.js execution environment for Lambda
// see https://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html
const DEFAULT_CONTEXT = {
  awsRegion: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION,
  functionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
  functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
  functionMemorySize: process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE,
  environment: process.env.ENVIRONMENT || process.env.STAGE // convention in our functions
}

class Logger {
  constructor ({
    correlationIds = CorrelationIds,
    level = process.env.LOG_LEVEL
  } = {}) {
    this.correlationIds = correlationIds
    this.level = (level || 'DEBUG').toUpperCase()
    this.originalLevel = this.level

    if (correlationIds.debugEnabled) {
      this.enableDebug()
    }
  }

  get context () {
    return {
      ...DEFAULT_CONTEXT,
      ...this.correlationIds.get()
    }
  }

  isEnabled (level) {
    return level >= (LogLevels[this.level] || LogLevels.DEBUG)
  }

  appendError (params, err) {
    if (!err) {
      return params
    }

    return {
      ...params || {},
      errorName: err.name,
      errorMessage: err.message,
      stackTrace: err.stack
    }
  }

  log (levelName, message, params) {
    const level = LogLevels[levelName]
    if (!this.isEnabled(level)) {
      return
    }

    const logMsg = {
      ...this.context,
      ...params,
      level,
      sLevel: levelName,
      message
    }

    const consoleMethods = {
      DEBUG: console.debug,
      INFO: console.info,
      WARN: console.warn,
      ERROR: console.error
    }

    // re-order message and params to appear earlier in the log row
    consoleMethods[levelName](JSON.stringify({ message, ...params, ...logMsg }, (key, value) => typeof value === 'bigint'
      ? value.toString()
      : value
    ))
  }

  debug (msg, params) {
    this.log('DEBUG', msg, params)
  }

  info (msg, params) {
    this.log('INFO', msg, params)
  }

  warn (msg, params, err) {
    const parameters = !err && params instanceof Error ? this.appendError({}, params) : this.appendError(params, err)
    this.log('WARN', msg, parameters)
  }

  error (msg, params, err) {
    const parameters = !err && params instanceof Error ? this.appendError({}, params) : this.appendError(params, err)
    this.log('ERROR', msg, parameters)
  }

  enableDebug () {
    this.level = 'DEBUG'
    return () => this.resetLevel()
  }

  resetLevel () {
    this.level = this.originalLevel
  }

  static debug (...args) {
    globalLogger.debug(...args)
  }

  static info (...args) {
    globalLogger.info(...args)
  }

  static warn (...args) {
    globalLogger.warn(...args)
  }

  static error (...args) {
    globalLogger.error(...args)
  }

  static enableDebug () {
    return globalLogger.enableDebug()
  }

  static resetLevel () {
    globalLogger.resetLevel()
  }

  static get level () {
    return globalLogger.level
  }
}

const globalLogger = new Logger()

module.exports = Logger


/***/ }),

/***/ "./deploy/lambda/edge/index.ts":
/*!*************************************!*\
  !*** ./deploy/lambda/edge/index.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handler = void 0;
const lambda_powertools_logger_1 = __importDefault(__webpack_require__(/*! @dazn/lambda-powertools-logger */ "./node_modules/@dazn/lambda-powertools-logger/index.js"));
const aws_jwt_verify_1 = __webpack_require__(/*! aws-jwt-verify */ "./node_modules/aws-jwt-verify/dist/cjs/index.js");
const handler = async (event, context, callback) => {
    lambda_powertools_logger_1.default.info('Start Auth');
    const userPoolId = process.env.USER_POOL_ID ? process.env.USER_POOL_ID : '';
    const tokenUse = 'id';
    const clientId = process.env.CLIENT_ID ? process.env.CLIENT_ID : '';
    const verifier = aws_jwt_verify_1.CognitoJwtVerifier.create({
        userPoolId,
        tokenUse,
        clientId,
    });
    const request = event.Records[0].cf.request;
    lambda_powertools_logger_1.default.info('headers', request);
    for (const cookie of request.headers['cookie']) {
        if (cookie.key === 'cookie') {
            // 認証OK
            try {
                const cookies = cookie.value.split(';');
                for (const c of cookies) {
                    if (c.split('idToken=')[1]) {
                        lambda_powertools_logger_1.default.info(c.split('idToken=')[1]);
                        const payload = await verifier.verify(c.split('idToken=')[1]);
                        lambda_powertools_logger_1.default.info('Token is valid. Payload:', payload);
                        callback(null, request);
                        return null;
                    }
                }
            }
            catch {
                lambda_powertools_logger_1.default.info('Token not valid!');
            }
        }
    }
    // 認証NG
    callback(null, {
        status: '401',
        statusDescription: 'Unauthorized',
        body: '<h1>401 Unauthorized</h1>',
    });
};
exports.handler = handler;


/***/ }),

/***/ "crypto":
/*!*************************!*\
  !*** external "crypto" ***!
  \*************************/
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ "https":
/*!************************!*\
  !*** external "https" ***!
  \************************/
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ "path":
/*!***********************!*\
  !*** external "path" ***!
  \***********************/
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ }),

/***/ "stream":
/*!*************************!*\
  !*** external "stream" ***!
  \*************************/
/***/ ((module) => {

"use strict";
module.exports = require("stream");

/***/ }),

/***/ "url":
/*!**********************!*\
  !*** external "url" ***!
  \**********************/
/***/ ((module) => {

"use strict";
module.exports = require("url");

/***/ }),

/***/ "util":
/*!***********************!*\
  !*** external "util" ***!
  \***********************/
/***/ ((module) => {

"use strict";
module.exports = require("util");

/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/asn1.js":
/*!******************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/asn1.js ***!
  \******************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utility to encode RSA public keys (a pair of modulus (n) and exponent (e)) into DER-encoding, per ASN.1 specification.
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.deconstructPublicKeyInDerFormat = exports.constructPublicKeyInDerFormat = void 0;
const error_js_1 = __webpack_require__(/*! ./error.js */ "./node_modules/aws-jwt-verify/dist/cjs/error.js");
/** Enum with possible values for supported ASN.1 classes */
var Asn1Class;
(function (Asn1Class) {
    Asn1Class[Asn1Class["Universal"] = 0] = "Universal";
})(Asn1Class || (Asn1Class = {}));
/** Enum with possible values for supported ASN.1 encodings */
var Asn1Encoding;
(function (Asn1Encoding) {
    Asn1Encoding[Asn1Encoding["Primitive"] = 0] = "Primitive";
    Asn1Encoding[Asn1Encoding["Constructed"] = 1] = "Constructed";
})(Asn1Encoding || (Asn1Encoding = {}));
/** Enum with possible values for supported ASN.1 tags */
var Asn1Tag;
(function (Asn1Tag) {
    Asn1Tag[Asn1Tag["BitString"] = 3] = "BitString";
    Asn1Tag[Asn1Tag["ObjectIdentifier"] = 6] = "ObjectIdentifier";
    Asn1Tag[Asn1Tag["Sequence"] = 16] = "Sequence";
    Asn1Tag[Asn1Tag["Null"] = 5] = "Null";
    Asn1Tag[Asn1Tag["Integer"] = 2] = "Integer";
})(Asn1Tag || (Asn1Tag = {}));
/**
 * Encode an ASN.1 identifier per ASN.1 spec (DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.1.2
 *
 * @param identifier - The ASN.1 identifier
 * @returns The buffer
 */
function encodeIdentifier(identifier) {
    const identifierAsNumber = (identifier.class << 7) |
        (identifier.primitiveOrConstructed << 5) |
        identifier.tag;
    return Buffer.from([identifierAsNumber]);
}
/**
 * Encode the length of an ASN.1 type per ASN.1 spec (DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.1.3
 *
 * @param length - The length of the ASN.1 type
 * @returns The buffer
 */
function encodeLength(length) {
    if (length < 128) {
        return Buffer.from([length]);
    }
    const integers = [];
    while (length > 0) {
        integers.push(length % 256);
        length = length >> 8;
    }
    integers.reverse();
    return Buffer.from([128 | integers.length, ...integers]);
}
/**
 * Encode a buffer (that represent an integer) as integer per ASN.1 spec (DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.3
 *
 * @param buffer - The buffer that represent an integer to encode
 * @returns The buffer
 */
function encodeBufferAsInteger(buffer) {
    return Buffer.concat([
        encodeIdentifier({
            class: Asn1Class.Universal,
            primitiveOrConstructed: Asn1Encoding.Primitive,
            tag: Asn1Tag.Integer,
        }),
        encodeLength(buffer.length),
        buffer,
    ]);
}
/**
 * Encode an object identifier (a string such as "1.2.840.113549.1.1.1") per ASN.1 spec (DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.19
 *
 * @param oid - The object identifier to encode
 * @returns The buffer
 */
function encodeObjectIdentifier(oid) {
    const oidComponents = oid.split(".").map((i) => parseInt(i));
    const firstSubidentifier = oidComponents[0] * 40 + oidComponents[1];
    const subsequentSubidentifiers = oidComponents
        .slice(2)
        .reduce((expanded, component) => {
        const bytes = [];
        do {
            bytes.push(component % 128);
            component = component >> 7;
        } while (component);
        return expanded.concat(bytes.map((b, index) => (index ? b + 128 : b)).reverse());
    }, []);
    const oidBuffer = Buffer.from([
        firstSubidentifier,
        ...subsequentSubidentifiers,
    ]);
    return Buffer.concat([
        encodeIdentifier({
            class: Asn1Class.Universal,
            primitiveOrConstructed: Asn1Encoding.Primitive,
            tag: Asn1Tag.ObjectIdentifier,
        }),
        encodeLength(oidBuffer.length),
        oidBuffer,
    ]);
}
/**
 * Encode a buffer as bit string per ASN.1 spec (DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.6
 *
 * @param buffer - The buffer to encode
 * @returns The buffer
 */
function encodeBufferAsBitString(buffer) {
    const bitString = Buffer.concat([Buffer.from([0]), buffer]);
    return Buffer.concat([
        encodeIdentifier({
            class: Asn1Class.Universal,
            primitiveOrConstructed: Asn1Encoding.Primitive,
            tag: Asn1Tag.BitString,
        }),
        encodeLength(bitString.length),
        bitString,
    ]);
}
/**
 * Encode a sequence of DER-encoded items per ASN.1 spec (DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.9
 *
 * @param sequenceItems - The sequence of DER-encoded items
 * @returns The buffer
 */
function encodeSequence(sequenceItems) {
    const concatenated = Buffer.concat(sequenceItems);
    return Buffer.concat([
        encodeIdentifier({
            class: Asn1Class.Universal,
            primitiveOrConstructed: Asn1Encoding.Constructed,
            tag: Asn1Tag.Sequence,
        }),
        encodeLength(concatenated.length),
        concatenated,
    ]);
}
/**
 * Encode null per ASN.1 spec (DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.8
 *
 * @returns The buffer
 */
function encodeNull() {
    return Buffer.concat([
        encodeIdentifier({
            class: Asn1Class.Universal,
            primitiveOrConstructed: Asn1Encoding.Primitive,
            tag: Asn1Tag.Null,
        }),
        encodeLength(0),
    ]);
}
/**
 * RSA encryption object identifier constant
 *
 * From: https://tools.ietf.org/html/rfc8017
 *
 * pkcs-1    OBJECT IDENTIFIER ::= {
 *     iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1
 * }
 *
 * -- When rsaEncryption is used in an AlgorithmIdentifier,
 * -- the parameters MUST be present and MUST be NULL.
 * --
 * rsaEncryption    OBJECT IDENTIFIER ::= { pkcs-1 1 }
 *
 * See also: http://www.oid-info.com/get/1.2.840.113549.1.1.1
 */
const ALGORITHM_RSA_ENCRYPTION = encodeSequence([
    encodeObjectIdentifier("1.2.840.113549.1.1.1"),
    encodeNull(), // parameters
]);
/**
 * Transform an RSA public key, which is a pair of modulus (n) and exponent (e),
 *  into a buffer per ASN.1 spec (DER-encoding)
 *
 * @param n - The modulus of the public key as buffer
 * @param e - The exponent of the public key as buffer
 * @returns The buffer, which is the public key encoded per ASN.1 spec (DER-encoding)
 */
function constructPublicKeyInDerFormat(n, e) {
    return encodeSequence([
        ALGORITHM_RSA_ENCRYPTION,
        encodeBufferAsBitString(encodeSequence([encodeBufferAsInteger(n), encodeBufferAsInteger(e)])),
    ]);
}
exports.constructPublicKeyInDerFormat = constructPublicKeyInDerFormat;
/**
 * Decode an ASN.1 identifier (a number) into its parts: class, primitiveOrConstructed, tag
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.1.2
 *
 * @param identifier - The identifier
 * @returns An object with properties class, primitiveOrConstructed, tag
 */
function decodeIdentifier(identifier) {
    if (identifier >> 3 === 0b11111) {
        throw new error_js_1.Asn1DecodingError("Decoding of identifier with tag > 30 not implemented");
    }
    return {
        class: identifier >> 6,
        primitiveOrConstructed: (identifier >> 5) & 0b001,
        tag: identifier & 0b11111, // bit 1-5
    };
}
/**
 * Decode an ASN.1 block of length value combinations,
 * and return the length and byte range of the first length value combination.
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.1.3 - 8.1.5
 *
 * @param blockOfLengthValues - The ASN.1 length value
 * @returns The length and byte range of the first included length value
 */
function decodeLengthValue(blockOfLengthValues) {
    if (!(blockOfLengthValues[0] & 0b10000000)) {
        return {
            length: blockOfLengthValues[0],
            firstByteOffset: 1,
            lastByteOffset: 1 + blockOfLengthValues[0],
        };
    }
    const nrLengthOctets = blockOfLengthValues[0] & 0b01111111;
    const length = Buffer.from(blockOfLengthValues.slice(1, 1 + 1 + nrLengthOctets)).readUIntBE(0, nrLengthOctets);
    return {
        length,
        firstByteOffset: 1 + nrLengthOctets,
        lastByteOffset: 1 + nrLengthOctets + length,
    };
}
/**
 * Decode an ASN.1 sequence into its constituent parts, each part being an identifier-length-value triplet
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.9
 *
 * @param sequenceValue - The ASN.1 sequence value
 * @returns Array of identifier-length-value triplets
 */
function decodeSequence(sequence) {
    const { tag } = decodeIdentifier(sequence[0]);
    if (tag !== Asn1Tag.Sequence) {
        throw new error_js_1.Asn1DecodingError(`Expected a sequence to decode, but got tag ${tag}`);
    }
    const { firstByteOffset, lastByteOffset } = decodeLengthValue(sequence.slice(1));
    const sequenceValue = sequence.slice(1 + firstByteOffset, 1 + 1 + lastByteOffset);
    const parts = [];
    let offset = 0;
    while (offset < sequenceValue.length) {
        // Silence false postive: accessing an octet in a Buffer at a particular index
        // is to be done with index operator: [index]
        // eslint-disable-next-line security/detect-object-injection
        const identifier = decodeIdentifier(sequenceValue[offset]);
        const next = decodeLengthValue(sequenceValue.slice(offset + 1));
        const value = sequenceValue.slice(offset + 1 + next.firstByteOffset, offset + 1 + next.lastByteOffset);
        parts.push({ identifier, length: next.length, value });
        offset += 1 + next.lastByteOffset;
    }
    return parts;
}
/**
 * Decode an ASN.1 sequence that is wrapped in a bit string
 * (Which is the way RSA public keys are encoded in ASN.1 DER-encoding)
 * See https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf chapter 8.6 and 8.9
 *
 * @param bitStringValue - The ASN.1 bit string value
 * @returns Array of identifier-length-value triplets
 */
function decodeBitStringWrappedSequenceValue(bitStringValue) {
    const wrappedSequence = bitStringValue.slice(1);
    return decodeSequence(wrappedSequence);
}
/**
 * Decode an ASN.1 DER-encoded public key, into its modulus (n) and exponent (e)
 *
 * @param publicKey - The ASN.1 DER-encoded public key
 * @returns Object with modulus (n) and exponent (e)
 */
function deconstructPublicKeyInDerFormat(publicKey) {
    const [, pubkeyinfo] = decodeSequence(publicKey);
    const [n, e] = decodeBitStringWrappedSequenceValue(pubkeyinfo.value);
    return { n: n.value, e: e.value };
}
exports.deconstructPublicKeyInDerFormat = deconstructPublicKeyInDerFormat;


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/assert.js":
/*!********************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/assert.js ***!
  \********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities to assert that supplied values match with expected values
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.assertIsNotPromise = exports.assertStringArraysOverlap = exports.assertStringArrayContainsString = exports.assertStringEquals = void 0;
const error_js_1 = __webpack_require__(/*! ./error.js */ "./node_modules/aws-jwt-verify/dist/cjs/error.js");
/**
 * Assert value is a non-empty string and equal to the expected value,
 * or throw an error otherwise
 *
 * @param name - Name for the value being checked
 * @param actual - The value to check
 * @param expected - The expected value
 * @param errorConstructor - Constructor for the concrete error to be thrown
 */
function assertStringEquals(name, actual, expected, errorConstructor = error_js_1.FailedAssertionError) {
    if (!actual) {
        throw new errorConstructor(`Missing ${name}. Expected: ${expected}`, actual, expected);
    }
    if (typeof actual !== "string") {
        throw new errorConstructor(`${name} is not of type string`, actual, expected);
    }
    if (expected !== actual) {
        throw new errorConstructor(`${name} not allowed: ${actual}. Expected: ${expected}`, actual, expected);
    }
}
exports.assertStringEquals = assertStringEquals;
/**
 * Assert value is a non-empty string and is indeed one of the expected values,
 * or throw an error otherwise
 *
 * @param name - Name for the value being checked
 * @param actual - The value to check
 * @param expected - The array of expected values. For your convenience you can provide
 * @param errorConstructor - Constructor for the concrete error to be thrown
 * a string here as well, which will mean an array with just that string
 */
function assertStringArrayContainsString(name, actual, expected, errorConstructor = error_js_1.FailedAssertionError) {
    if (!actual) {
        throw new errorConstructor(`Missing ${name}. ${expectationMessage(expected)}`, actual, expected);
    }
    if (typeof actual !== "string") {
        throw new errorConstructor(`${name} is not of type string`, actual, expected);
    }
    return assertStringArraysOverlap(name, actual, expected, errorConstructor);
}
exports.assertStringArrayContainsString = assertStringArrayContainsString;
/**
 * Assert value is an array of strings, where at least one of the strings is indeed one of the expected values,
 * or throw an error otherwise
 *
 * @param name - Name for the value being checked
 * @param actual - The value to check, must be an array of strings, or a single string (which will be treated
 * as an array with just that string)
 * @param expected - The array of expected values. For your convenience you can provide
 * a string here as well, which will mean an array with just that string
 * @param errorConstructor - Constructor for the concrete error to be thrown
 */
function assertStringArraysOverlap(name, actual, expected, errorConstructor = error_js_1.FailedAssertionError) {
    if (!actual) {
        throw new errorConstructor(`Missing ${name}. ${expectationMessage(expected)}`, actual, expected);
    }
    const expectedAsSet = new Set(Array.isArray(expected) ? expected : [expected]);
    if (typeof actual === "string") {
        actual = [actual];
    }
    if (!Array.isArray(actual)) {
        throw new errorConstructor(`${name} is not an array`, actual, expected);
    }
    const overlaps = actual.some((actualItem) => {
        if (typeof actualItem !== "string") {
            throw new errorConstructor(`${name} includes elements that are not of type string`, actual, expected);
        }
        return expectedAsSet.has(actualItem);
    });
    if (!overlaps) {
        throw new errorConstructor(`${name} not allowed: ${actual.join(", ")}. ${expectationMessage(expected)}`, actual, expected);
    }
}
exports.assertStringArraysOverlap = assertStringArraysOverlap;
/**
 * Get a nicely readable message regarding an expectation
 *
 * @param expected - The expected value.
 */
function expectationMessage(expected) {
    if (Array.isArray(expected)) {
        if (expected.length > 1) {
            return `Expected one of: ${expected.join(", ")}`;
        }
        return `Expected: ${expected[0]}`;
    }
    return `Expected: ${expected}`;
}
/**
 * Assert value is not a promise, or throw an error otherwise
 *
 * @param actual - The value to check
 * @param errorFactory - Function that returns the error to be thrown
 */
function assertIsNotPromise(actual, errorFactory) {
    if (actual && typeof actual.then === "function") {
        throw errorFactory();
    }
}
exports.assertIsNotPromise = assertIsNotPromise;


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/cognito-verifier.js":
/*!******************************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/cognito-verifier.js ***!
  \******************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CognitoJwtVerifier = void 0;
const error_js_1 = __webpack_require__(/*! ./error.js */ "./node_modules/aws-jwt-verify/dist/cjs/error.js");
const jwt_rsa_js_1 = __webpack_require__(/*! ./jwt-rsa.js */ "./node_modules/aws-jwt-verify/dist/cjs/jwt-rsa.js");
const assert_js_1 = __webpack_require__(/*! ./assert.js */ "./node_modules/aws-jwt-verify/dist/cjs/assert.js");
/**
 * Validate claims of a decoded Cognito JWT.
 * This function throws an error in case there's any validation issue.
 *
 * @param payload - The JSON parsed payload of the Cognito JWT
 * @param options - Validation options
 * @param options.groups - The cognito groups, of which at least one must be present in the JWT's cognito:groups claim
 * @param options.tokenUse - The required token use of the JWT: "id" or "access"
 * @param options.clientId - The required clientId of the JWT. May be an array of string, of which at least one must match
 * @returns void
 */
function validateCognitoJwtFields(payload, options) {
    // Check groups
    if (options.groups != null) {
        (0, assert_js_1.assertStringArraysOverlap)("Cognito group", payload["cognito:groups"], options.groups, error_js_1.CognitoJwtInvalidGroupError);
    }
    // Check token use
    (0, assert_js_1.assertStringArrayContainsString)("Token use", payload.token_use, ["id", "access"], error_js_1.CognitoJwtInvalidTokenUseError);
    if (options.tokenUse !== null) {
        if (options.tokenUse === undefined) {
            throw new error_js_1.ParameterValidationError("tokenUse must be provided or set to null explicitly");
        }
        (0, assert_js_1.assertStringEquals)("Token use", payload.token_use, options.tokenUse, error_js_1.CognitoJwtInvalidTokenUseError);
    }
    // Check clientId aka audience
    if (options.clientId !== null) {
        if (options.clientId === undefined) {
            throw new error_js_1.ParameterValidationError("clientId must be provided or set to null explicitly");
        }
        if (payload.token_use === "id") {
            (0, assert_js_1.assertStringArrayContainsString)('Client ID ("audience")', payload.aud, options.clientId, error_js_1.CognitoJwtInvalidClientIdError);
        }
        else {
            (0, assert_js_1.assertStringArrayContainsString)("Client ID", payload.client_id, options.clientId, error_js_1.CognitoJwtInvalidClientIdError);
        }
    }
}
/**
 * Class representing a verifier for JWTs signed by Amazon Cognito
 */
class CognitoJwtVerifier extends jwt_rsa_js_1.JwtRsaVerifierBase {
    constructor(props, jwksCache) {
        const issuerConfig = Array.isArray(props)
            ? props.map((p) => ({
                ...p,
                ...CognitoJwtVerifier.parseUserPoolId(p.userPoolId),
                audience: null, // checked instead by validateCognitoJwtFields
            }))
            : {
                ...props,
                ...CognitoJwtVerifier.parseUserPoolId(props.userPoolId),
                audience: null, // checked instead by validateCognitoJwtFields
            };
        super(issuerConfig, jwksCache);
    }
    /**
     * Parse a User Pool ID, to extract the issuer and JWKS URI
     *
     * @param userPoolId The User Pool ID
     * @returns The issuer and JWKS URI for the User Pool
     */
    static parseUserPoolId(userPoolId) {
        // Disable safe regexp check as userPoolId is provided by developer, i.e. is not user input
        // eslint-disable-next-line security/detect-unsafe-regex
        const match = userPoolId.match(/^(?<region>(\w+-)?\w+-\w+-\d)+_\w+$/);
        if (!match) {
            throw new error_js_1.ParameterValidationError(`Invalid Cognito User Pool ID: ${userPoolId}`);
        }
        const region = match.groups.region;
        const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
        return {
            issuer,
            jwksUri: `${issuer}/.well-known/jwks.json`,
        };
    }
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    static create(verifyProperties, additionalProperties) {
        return new this(verifyProperties, additionalProperties?.jwksCache);
    }
    /**
     * Verify (synchronously) a JWT that is signed by Amazon Cognito.
     *
     * @param jwt The JWT, as string
     * @param props Verification properties
     * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
     */
    verifySync(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        this.verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties);
        try {
            validateCognitoJwtFields(decomposedJwt.payload, verifyProperties);
        }
        catch (err) {
            if (verifyProperties.includeRawJwtInErrors &&
                err instanceof error_js_1.JwtInvalidClaimError) {
                throw err.withRawJwt(decomposedJwt);
            }
            throw err;
        }
        return decomposedJwt.payload;
    }
    /**
     * Verify (asynchronously) a JWT that is signed by Amazon Cognito.
     * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
     * in case it is not yet available in the cache.
     *
     * @param jwt The JWT, as string
     * @param props Verification properties
     * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
     */
    async verify(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        await this.verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties);
        try {
            validateCognitoJwtFields(decomposedJwt.payload, verifyProperties);
        }
        catch (err) {
            if (verifyProperties.includeRawJwtInErrors &&
                err instanceof error_js_1.JwtInvalidClaimError) {
                throw err.withRawJwt(decomposedJwt);
            }
            throw err;
        }
        return decomposedJwt.payload;
    }
    /**
     * This method loads a JWKS that you provide, into the JWKS cache, so that it is
     * available for JWT verification. Use this method to speed up the first JWT verification
     * (when the JWKS would otherwise have to be downloaded from the JWKS uri), or to provide the JWKS
     * in case the JwtVerifier does not have internet access to download the JWKS
     *
     * @param jwks The JWKS
     * @param userPoolId The userPoolId for which you want to cache the JWKS
     *  Supply this field, if you instantiated the CognitoJwtVerifier with multiple userPoolIds
     * @returns void
     */
    cacheJwks(...[jwks, userPoolId]) {
        let issuer;
        if (userPoolId !== undefined) {
            issuer = CognitoJwtVerifier.parseUserPoolId(userPoolId).issuer;
        }
        else if (this.expectedIssuers.length > 1) {
            throw new error_js_1.ParameterValidationError("userPoolId must be provided");
        }
        const issuerConfig = this.getIssuerConfig(issuer);
        super.cacheJwks(jwks, issuerConfig.issuer);
    }
}
exports.CognitoJwtVerifier = CognitoJwtVerifier;


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/error.js":
/*!*******************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/error.js ***!
  \*******************************************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NonRetryableFetchError = exports.FetchError = exports.JwkInvalidKtyError = exports.JwkInvalidUseError = exports.JwksNotAvailableInCacheError = exports.WaitPeriodNotYetEndedJwkError = exports.KidNotFoundInJwksError = exports.JwtWithoutValidKidError = exports.JwkValidationError = exports.JwksValidationError = exports.Asn1DecodingError = exports.CognitoJwtInvalidClientIdError = exports.CognitoJwtInvalidTokenUseError = exports.CognitoJwtInvalidGroupError = exports.JwtNotBeforeError = exports.JwtExpiredError = exports.JwtInvalidScopeError = exports.JwtInvalidAudienceError = exports.JwtInvalidIssuerError = exports.JwtInvalidClaimError = exports.JwtInvalidSignatureAlgorithmError = exports.JwtInvalidSignatureError = exports.ParameterValidationError = exports.JwtParseError = exports.FailedAssertionError = exports.JwtBaseError = void 0;
/**
 * Base Error for all other errors in this file
 */
class JwtBaseError extends Error {
}
exports.JwtBaseError = JwtBaseError;
/**
 * An error that is raised because an actual value does not match with the expected value
 */
class FailedAssertionError extends JwtBaseError {
    constructor(msg, actual, expected) {
        super(msg);
        this.failedAssertion = {
            actual,
            expected,
        };
    }
}
exports.FailedAssertionError = FailedAssertionError;
/**
 * JWT errors
 */
class JwtParseError extends JwtBaseError {
    constructor(msg, error) {
        const message = error != null ? `${msg}: ${error}` : msg;
        super(message);
    }
}
exports.JwtParseError = JwtParseError;
class ParameterValidationError extends JwtBaseError {
}
exports.ParameterValidationError = ParameterValidationError;
class JwtInvalidSignatureError extends JwtBaseError {
}
exports.JwtInvalidSignatureError = JwtInvalidSignatureError;
class JwtInvalidSignatureAlgorithmError extends FailedAssertionError {
}
exports.JwtInvalidSignatureAlgorithmError = JwtInvalidSignatureAlgorithmError;
class JwtInvalidClaimError extends FailedAssertionError {
    withRawJwt({ header, payload }) {
        this.rawJwt = {
            header,
            payload,
        };
        return this;
    }
}
exports.JwtInvalidClaimError = JwtInvalidClaimError;
class JwtInvalidIssuerError extends JwtInvalidClaimError {
}
exports.JwtInvalidIssuerError = JwtInvalidIssuerError;
class JwtInvalidAudienceError extends JwtInvalidClaimError {
}
exports.JwtInvalidAudienceError = JwtInvalidAudienceError;
class JwtInvalidScopeError extends JwtInvalidClaimError {
}
exports.JwtInvalidScopeError = JwtInvalidScopeError;
class JwtExpiredError extends JwtInvalidClaimError {
}
exports.JwtExpiredError = JwtExpiredError;
class JwtNotBeforeError extends JwtInvalidClaimError {
}
exports.JwtNotBeforeError = JwtNotBeforeError;
/**
 * Amazon Cognito specific erros
 */
class CognitoJwtInvalidGroupError extends JwtInvalidClaimError {
}
exports.CognitoJwtInvalidGroupError = CognitoJwtInvalidGroupError;
class CognitoJwtInvalidTokenUseError extends JwtInvalidClaimError {
}
exports.CognitoJwtInvalidTokenUseError = CognitoJwtInvalidTokenUseError;
class CognitoJwtInvalidClientIdError extends JwtInvalidClaimError {
}
exports.CognitoJwtInvalidClientIdError = CognitoJwtInvalidClientIdError;
/**
 * ASN.1 errors
 */
class Asn1DecodingError extends JwtBaseError {
}
exports.Asn1DecodingError = Asn1DecodingError;
/**
 * JWK errors
 */
class JwksValidationError extends JwtBaseError {
}
exports.JwksValidationError = JwksValidationError;
class JwkValidationError extends JwtBaseError {
}
exports.JwkValidationError = JwkValidationError;
class JwtWithoutValidKidError extends JwtBaseError {
}
exports.JwtWithoutValidKidError = JwtWithoutValidKidError;
class KidNotFoundInJwksError extends JwtBaseError {
}
exports.KidNotFoundInJwksError = KidNotFoundInJwksError;
class WaitPeriodNotYetEndedJwkError extends JwtBaseError {
}
exports.WaitPeriodNotYetEndedJwkError = WaitPeriodNotYetEndedJwkError;
class JwksNotAvailableInCacheError extends JwtBaseError {
}
exports.JwksNotAvailableInCacheError = JwksNotAvailableInCacheError;
class JwkInvalidUseError extends FailedAssertionError {
}
exports.JwkInvalidUseError = JwkInvalidUseError;
class JwkInvalidKtyError extends FailedAssertionError {
}
exports.JwkInvalidKtyError = JwkInvalidKtyError;
/**
 * HTTPS fetch errors
 */
class FetchError extends JwtBaseError {
    constructor(uri, msg) {
        super(`Failed to fetch ${uri}: ${msg}`);
    }
}
exports.FetchError = FetchError;
class NonRetryableFetchError extends FetchError {
}
exports.NonRetryableFetchError = NonRetryableFetchError;


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/https.js":
/*!*******************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/https.js ***!
  \*******************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utilities for fetching the JWKS URI, to get the public keys with which to verify JWTs
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.fetchJson = exports.SimpleJsonFetcher = void 0;
const https_1 = __webpack_require__(/*! https */ "https");
const stream_1 = __webpack_require__(/*! stream */ "stream");
const util_1 = __webpack_require__(/*! util */ "util");
const safe_json_parse_js_1 = __webpack_require__(/*! ./safe-json-parse.js */ "./node_modules/aws-jwt-verify/dist/cjs/safe-json-parse.js");
const error_js_1 = __webpack_require__(/*! ./error.js */ "./node_modules/aws-jwt-verify/dist/cjs/error.js");
/**
 * HTTPS Fetcher for URIs with JSON body
 *
 * @param defaultRequestOptions - The default RequestOptions to use on individual HTTPS requests
 */
class SimpleJsonFetcher {
    constructor(props) {
        this.defaultRequestOptions = {
            timeout: 500,
            responseTimeout: 1500,
            ...props?.defaultRequestOptions,
        };
    }
    /**
     * Execute a HTTPS request (with 1 immediate retry in case of errors)
     * @param uri - The URI
     * @param requestOptions - The RequestOptions to use
     * @param data - Data to send to the URI (e.g. POST data)
     * @returns - The response as parsed JSON
     */
    async fetch(uri, requestOptions, data) {
        requestOptions = { ...this.defaultRequestOptions, ...requestOptions };
        try {
            return await fetchJson(uri, requestOptions, data);
        }
        catch (err) {
            if (err instanceof error_js_1.NonRetryableFetchError) {
                throw err;
            }
            // Retry once, immediately
            return fetchJson(uri, requestOptions, data);
        }
    }
}
exports.SimpleJsonFetcher = SimpleJsonFetcher;
/**
 * Execute a HTTPS request
 * @param uri - The URI
 * @param requestOptions - The RequestOptions to use
 * @param data - Data to send to the URI (e.g. POST data)
 * @returns - The response as parsed JSON
 */
async function fetchJson(uri, requestOptions, data) {
    let responseTimeout;
    return new Promise((resolve, reject) => {
        const req = (0, https_1.request)(uri, {
            method: "GET",
            ...requestOptions,
        }, (response) => {
            // Capture response data
            // @types/node is incomplete so cast to any
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            stream_1.pipeline([
                response,
                getJsonDestination(uri, response.statusCode, response.headers),
            ], done);
        });
        if (requestOptions?.responseTimeout) {
            responseTimeout = setTimeout(() => done(new error_js_1.FetchError(uri, `Response time-out (after ${requestOptions.responseTimeout} ms.)`)), requestOptions.responseTimeout);
            responseTimeout.unref(); // Don't block Node from exiting
        }
        function done(...args) {
            if (responseTimeout)
                clearTimeout(responseTimeout);
            if (args[0] == null) {
                resolve(args[1]);
                return;
            }
            // In case of errors, let the Agent (if any) know to abandon the socket
            // This is probably best, because the socket may have become stale
            /* istanbul ignore next */
            req.socket?.emit("agentRemove");
            // Turn error into FetchError so the URI is nicely captured in the message
            let error = args[0];
            if (!(error instanceof error_js_1.FetchError)) {
                error = new error_js_1.FetchError(uri, error.message);
            }
            req.destroy();
            reject(error);
        }
        // Handle errors while sending request
        req.on("error", done);
        // Signal end of request (include optional data)
        req.end(data);
    });
}
exports.fetchJson = fetchJson;
/**
 * Ensures the HTTPS response contains valid JSON
 *
 * @param uri - The URI you were requesting
 * @param statusCode - The response status code to your HTTPS request
 * @param headers - The response headers to your HTTPS request
 *
 * @returns - Async function that can be used as destination in a stream.pipeline, it will return the JSON, if valid, or throw an error otherwise
 */
function getJsonDestination(uri, statusCode, headers) {
    return async (responseIterable) => {
        if (statusCode === 429) {
            throw new error_js_1.FetchError(uri, "Too many requests");
        }
        else if (statusCode !== 200) {
            throw new error_js_1.NonRetryableFetchError(uri, `Status code is ${statusCode}, expected 200`);
        }
        if (!headers["content-type"]?.toLowerCase().startsWith("application/json")) {
            throw new error_js_1.NonRetryableFetchError(uri, `Content-type is "${headers["content-type"]}", expected "application/json"`);
        }
        const collected = [];
        for await (const chunk of responseIterable) {
            collected.push(chunk);
        }
        try {
            return (0, safe_json_parse_js_1.safeJsonParse)(new util_1.TextDecoder("utf8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(collected)));
        }
        catch (err) {
            throw new error_js_1.NonRetryableFetchError(uri, err);
        }
    };
}


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/index.js":
/*!*******************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/index.js ***!
  \*******************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CognitoJwtVerifier = exports.JwtRsaVerifier = void 0;
var jwt_rsa_js_1 = __webpack_require__(/*! ./jwt-rsa.js */ "./node_modules/aws-jwt-verify/dist/cjs/jwt-rsa.js");
Object.defineProperty(exports, "JwtRsaVerifier", ({ enumerable: true, get: function () { return jwt_rsa_js_1.JwtRsaVerifier; } }));
var cognito_verifier_js_1 = __webpack_require__(/*! ./cognito-verifier.js */ "./node_modules/aws-jwt-verify/dist/cjs/cognito-verifier.js");
Object.defineProperty(exports, "CognitoJwtVerifier", ({ enumerable: true, get: function () { return cognito_verifier_js_1.CognitoJwtVerifier; } }));


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/jwk.js":
/*!*****************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/jwk.js ***!
  \*****************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SimpleJwksCache = exports.SimplePenaltyBox = exports.isJwk = exports.isJwks = exports.assertIsJwk = exports.assertIsJwks = exports.fetchJwk = exports.fetchJwks = void 0;
const https_js_1 = __webpack_require__(/*! ./https.js */ "./node_modules/aws-jwt-verify/dist/cjs/https.js");
const safe_json_parse_js_1 = __webpack_require__(/*! ./safe-json-parse.js */ "./node_modules/aws-jwt-verify/dist/cjs/safe-json-parse.js");
const error_js_1 = __webpack_require__(/*! ./error.js */ "./node_modules/aws-jwt-verify/dist/cjs/error.js");
const optionalJwkFieldNames = [
    "alg", // https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
];
const mandatoryJwkFieldNames = [
    "e",
    "kid",
    "kty",
    "n",
    "use", // https://datatracker.ietf.org/doc/html/rfc7517#section-4.2 NOTE: considered mandatory by this library
];
async function fetchJwks(jwksUri) {
    const jwks = await (0, https_js_1.fetchJson)(jwksUri);
    assertIsJwks(jwks);
    return jwks;
}
exports.fetchJwks = fetchJwks;
async function fetchJwk(jwksUri, decomposedJwt) {
    if (!decomposedJwt.header.kid) {
        throw new error_js_1.JwtWithoutValidKidError("JWT header does not have valid kid claim");
    }
    const jwk = (await fetchJwks(jwksUri)).keys.find((key) => key.kid === decomposedJwt.header.kid);
    if (!jwk) {
        throw new error_js_1.KidNotFoundInJwksError(`JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`);
    }
    return jwk;
}
exports.fetchJwk = fetchJwk;
function assertIsJwks(jwks) {
    if (!jwks) {
        throw new error_js_1.JwksValidationError("JWKS empty");
    }
    if (!(0, safe_json_parse_js_1.isJsonObject)(jwks)) {
        throw new error_js_1.JwksValidationError("JWKS should be an object");
    }
    if (!Object.keys(jwks).includes("keys")) {
        throw new error_js_1.JwksValidationError("JWKS does not include keys");
    }
    if (!Array.isArray(jwks.keys)) {
        throw new error_js_1.JwksValidationError("JWKS keys should be an array");
    }
    for (const jwk of jwks.keys) {
        assertIsJwk(jwk);
    }
}
exports.assertIsJwks = assertIsJwks;
function assertIsJwk(jwk) {
    if (!jwk) {
        throw new error_js_1.JwkValidationError("JWK empty");
    }
    if (!(0, safe_json_parse_js_1.isJsonObject)(jwk)) {
        throw new error_js_1.JwkValidationError("JWK should be an object");
    }
    for (const field of mandatoryJwkFieldNames) {
        // disable eslint rule because `field` is trusted
        // eslint-disable-next-line security/detect-object-injection
        if (typeof jwk[field] !== "string") {
            throw new error_js_1.JwkValidationError(`JWK ${field} should be a string`);
        }
    }
    for (const field of optionalJwkFieldNames) {
        // disable eslint rule because `field` is trusted
        // eslint-disable-next-line security/detect-object-injection
        if (field in jwk && typeof jwk[field] !== "string") {
            throw new error_js_1.JwkValidationError(`JWK ${field} should be a string`);
        }
    }
}
exports.assertIsJwk = assertIsJwk;
function isJwks(jwks) {
    try {
        assertIsJwks(jwks);
        return true;
    }
    catch {
        return false;
    }
}
exports.isJwks = isJwks;
function isJwk(jwk) {
    try {
        assertIsJwk(jwk);
        return true;
    }
    catch {
        return false;
    }
}
exports.isJwk = isJwk;
class SimplePenaltyBox {
    constructor(props) {
        this.waitingUris = new Map();
        this.waitSeconds = props?.waitSeconds ?? 10;
    }
    async wait(jwksUri) {
        // SimplePenaltyBox does not actually wait but bluntly throws an error
        // Any waiting and retries are expected to be done upstream (e.g. in the browser / app)
        if (this.waitingUris.has(jwksUri)) {
            throw new error_js_1.WaitPeriodNotYetEndedJwkError("Not allowed to fetch JWKS yet, still waiting for back off period to end");
        }
    }
    release(jwksUri) {
        const i = this.waitingUris.get(jwksUri);
        if (i) {
            clearTimeout(i);
            this.waitingUris.delete(jwksUri);
        }
    }
    registerFailedAttempt(jwksUri) {
        const i = setTimeout(() => {
            this.waitingUris.delete(jwksUri);
        }, this.waitSeconds * 1000).unref();
        this.waitingUris.set(jwksUri, i);
    }
    registerSuccessfulAttempt(jwksUri) {
        this.release(jwksUri);
    }
}
exports.SimplePenaltyBox = SimplePenaltyBox;
class SimpleJwksCache {
    constructor(props) {
        this.jwksCache = new Map();
        this.fetchingJwks = new Map();
        this.penaltyBox = props?.penaltyBox ?? new SimplePenaltyBox();
        this.fetcher = props?.fetcher ?? new https_js_1.SimpleJsonFetcher();
    }
    addJwks(jwksUri, jwks) {
        this.jwksCache.set(jwksUri, jwks);
    }
    async getJwks(jwksUri) {
        const existingFetch = this.fetchingJwks.get(jwksUri);
        if (existingFetch) {
            return existingFetch;
        }
        const jwksPromise = this.fetcher.fetch(jwksUri).then((res) => {
            assertIsJwks(res);
            return res;
        });
        this.fetchingJwks.set(jwksUri, jwksPromise);
        let jwks;
        try {
            jwks = await jwksPromise;
        }
        finally {
            this.fetchingJwks.delete(jwksUri);
        }
        this.jwksCache.set(jwksUri, jwks);
        return jwks;
    }
    getCachedJwk(jwksUri, decomposedJwt) {
        if (typeof decomposedJwt.header.kid !== "string") {
            throw new error_js_1.JwtWithoutValidKidError("JWT header does not have valid kid claim");
        }
        if (!this.jwksCache.has(jwksUri)) {
            throw new error_js_1.JwksNotAvailableInCacheError(`JWKS for uri ${jwksUri} not yet available in cache`);
        }
        const jwk = this.jwksCache
            .get(jwksUri)
            .keys.find((key) => key.kid === decomposedJwt.header.kid);
        if (!jwk) {
            throw new error_js_1.KidNotFoundInJwksError(`JWK for kid ${decomposedJwt.header.kid} not found in the JWKS`);
        }
        return jwk;
    }
    async getJwk(jwksUri, decomposedJwt) {
        if (typeof decomposedJwt.header.kid !== "string") {
            throw new error_js_1.JwtWithoutValidKidError("JWT header does not have valid kid claim");
        }
        // Try to get JWK from cache:
        let jwk = this.jwksCache
            .get(jwksUri)
            ?.keys.find((key) => key.kid === decomposedJwt.header.kid);
        if (jwk) {
            return jwk;
        }
        // Await any wait period that is currently in effect
        // This prevents us from flooding the JWKS URI with requests
        await this.penaltyBox.wait(jwksUri, decomposedJwt.header.kid);
        // Fetch the JWKS and (try to) locate the JWK
        const jwks = await this.getJwks(jwksUri);
        jwk = jwks.keys.find((key) => key.kid === decomposedJwt.header.kid);
        // If the JWK could not be located, someone might be messing around with us
        // Register the failed attempt with the penaltyBox, so it can enforce a wait period
        // before trying again next time (instead of flooding the JWKS URI with requests)
        if (!jwk) {
            this.penaltyBox.registerFailedAttempt(jwksUri, decomposedJwt.header.kid);
            throw new error_js_1.KidNotFoundInJwksError(`JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`);
        }
        else {
            this.penaltyBox.registerSuccessfulAttempt(jwksUri, decomposedJwt.header.kid);
        }
        return jwk;
    }
}
exports.SimpleJwksCache = SimpleJwksCache;


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/jwt-rsa.js":
/*!*********************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/jwt-rsa.js ***!
  \*********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.KeyObjectCache = exports.transformJwkToKeyObject = exports.JwtRsaVerifier = exports.JwtRsaVerifierBase = exports.verifyJwtSync = exports.verifyJwt = exports.JwtSignatureAlgorithms = void 0;
const crypto_1 = __webpack_require__(/*! crypto */ "crypto");
const url_1 = __webpack_require__(/*! url */ "url");
const path_1 = __webpack_require__(/*! path */ "path");
const jwk_js_1 = __webpack_require__(/*! ./jwk.js */ "./node_modules/aws-jwt-verify/dist/cjs/jwk.js");
const asn1_js_1 = __webpack_require__(/*! ./asn1.js */ "./node_modules/aws-jwt-verify/dist/cjs/asn1.js");
const assert_js_1 = __webpack_require__(/*! ./assert.js */ "./node_modules/aws-jwt-verify/dist/cjs/assert.js");
const jwt_js_1 = __webpack_require__(/*! ./jwt.js */ "./node_modules/aws-jwt-verify/dist/cjs/jwt.js");
const error_js_1 = __webpack_require__(/*! ./error.js */ "./node_modules/aws-jwt-verify/dist/cjs/error.js");
/**
 * Enum to map supported JWT signature algorithms with OpenSSL message digest algorithm names
 */
var JwtSignatureAlgorithms;
(function (JwtSignatureAlgorithms) {
    JwtSignatureAlgorithms["RS256"] = "RSA-SHA256";
    JwtSignatureAlgorithms["RS384"] = "RSA-SHA384";
    JwtSignatureAlgorithms["RS512"] = "RSA-SHA512";
})(JwtSignatureAlgorithms = exports.JwtSignatureAlgorithms || (exports.JwtSignatureAlgorithms = {}));
/**
 * Verify a JWTs signature agains a JWK. This function throws an error if the JWT is not valid
 *
 * @param header The decoded and JSON parsed JWT header
 * @param headerB64 The JWT header in base64 encoded form
 * @param payload The decoded and JSON parsed JWT payload
 * @param payloadB64 The JWT payload in base64 encoded form
 * @param signatureB64 The JWT signature in base64 encoded form
 * @param jwk The JWK with which the JWT was signed
 * @param jwkToKeyObjectTransformer Function to transform the JWK into a Node.js native key object
 * @returns void
 */
function verifySignatureAgainstJwk(header, headerB64, payload, payloadB64, signatureB64, jwk, jwkToKeyObjectTransformer = exports.transformJwkToKeyObject) {
    // Check JWK use
    (0, assert_js_1.assertStringEquals)("JWK use", jwk.use, "sig", error_js_1.JwkInvalidUseError);
    // Check JWK kty
    (0, assert_js_1.assertStringEquals)("JWK kty", jwk.kty, "RSA", error_js_1.JwkInvalidKtyError);
    // Check that JWT signature algorithm matches JWK
    if (jwk.alg) {
        (0, assert_js_1.assertStringEquals)("JWT signature algorithm", header.alg, jwk.alg, error_js_1.JwtInvalidSignatureAlgorithmError);
    }
    // Check JWT signature algorithm is one of RS256, RS384, RS512
    (0, assert_js_1.assertStringArrayContainsString)("JWT signature algorithm", header.alg, ["RS256", "RS384", "RS512"], error_js_1.JwtInvalidSignatureAlgorithmError);
    // Convert JWK modulus and exponent into DER public key
    const publicKey = jwkToKeyObjectTransformer(jwk, payload.iss, header.kid);
    // Verify the JWT signature
    const valid = (0, crypto_1.createVerify)(JwtSignatureAlgorithms[header.alg])
        .update(`${headerB64}.${payloadB64}`)
        .verify(publicKey, signatureB64, "base64");
    if (!valid) {
        throw new error_js_1.JwtInvalidSignatureError("Invalid signature");
    }
}
/**
 * Verify a JWT asynchronously (thus allowing for the JWKS to be fetched from the JWKS URI)
 *
 * @param jwt The JWT
 * @param jwksUri The JWKS URI, where the JWKS can be fetched from
 * @param options Verification options
 * @param jwkFetcher A function that can execute the fetch of the JWKS from the JWKS URI
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a Node.js native key object
 * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
 */
async function verifyJwt(jwt, jwksUri, options, jwkFetcher, jwkToKeyObjectTransformer) {
    return verifyDecomposedJwt((0, jwt_js_1.decomposeJwt)(jwt), jwksUri, options, jwkFetcher, jwkToKeyObjectTransformer);
}
exports.verifyJwt = verifyJwt;
/**
 * Verify (asynchronously) a JWT that is already decomposed (by function `decomposeJwt`)
 *
 * @param decomposedJwt The decomposed JWT
 * @param jwksUri The JWKS URI, where the JWKS can be fetched from
 * @param options Verification options
 * @param jwkFetcher A function that can execute the fetch of the JWKS from the JWKS URI
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a Node.js native key object
 * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
 */
async function verifyDecomposedJwt(decomposedJwt, jwksUri, options, jwkFetcher = jwk_js_1.fetchJwk, jwkToKeyObjectTransformer) {
    const { header, headerB64, payload, payloadB64, signatureB64 } = decomposedJwt;
    const jwk = await jwkFetcher(jwksUri, decomposedJwt);
    verifySignatureAgainstJwk(header, headerB64, payload, payloadB64, signatureB64, jwk, jwkToKeyObjectTransformer);
    try {
        (0, jwt_js_1.validateJwtFields)(payload, options);
        if (options.customJwtCheck) {
            await options.customJwtCheck({ header, payload, jwk });
        }
    }
    catch (err) {
        if (options.includeRawJwtInErrors && err instanceof error_js_1.JwtInvalidClaimError) {
            throw err.withRawJwt(decomposedJwt);
        }
        throw err;
    }
    return payload;
}
/**
 * Verify a JWT synchronously, using a JWKS or JWK that has already been fetched
 *
 * @param jwt The JWT
 * @param jwkOrJwks The JWKS that includes the right JWK (indexed by kid). Alternatively, provide the right JWK directly
 * @param options Verification options
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a Node.js native key object
 * @returns The (JSON parsed) payload of the JWT––if the JWT is valid, otherwise an error is thrown
 */
function verifyJwtSync(jwt, jwkOrJwks, options, jwkToKeyObjectTransformer) {
    return verifyDecomposedJwtSync((0, jwt_js_1.decomposeJwt)(jwt), jwkOrJwks, options, jwkToKeyObjectTransformer);
}
exports.verifyJwtSync = verifyJwtSync;
/**
 * Verify (synchronously) a JWT that is already decomposed (by function `decomposeJwt`)
 *
 * @param decomposedJwt The decomposed JWT
 * @param jwkOrJwks The JWKS that includes the right JWK (indexed by kid). Alternatively, provide the right JWK directly
 * @param options Verification options
 * @param jwkToKeyObjectTransformer A function that can transform a JWK into a Node.js native key object
 * @returns The (JSON parsed) payload of the JWT––if the JWT is valid, otherwise an error is thrown
 */
function verifyDecomposedJwtSync(decomposedJwt, jwkOrJwks, options, jwkToKeyObjectTransformer) {
    const { header, headerB64, payload, payloadB64, signatureB64 } = decomposedJwt;
    let jwk;
    if ((0, jwk_js_1.isJwk)(jwkOrJwks)) {
        jwk = jwkOrJwks;
    }
    else if ((0, jwk_js_1.isJwks)(jwkOrJwks)) {
        const locatedJwk = jwkOrJwks.keys.find((key) => key.kid === header.kid);
        if (!locatedJwk) {
            throw new error_js_1.KidNotFoundInJwksError(`JWK for kid ${header.kid} not found in the JWKS`);
        }
        jwk = locatedJwk;
    }
    else {
        throw new error_js_1.ParameterValidationError([
            `Expected a valid JWK or JWKS (parsed as JavaScript object), but received: ${jwkOrJwks}.`,
            "If you're passing a JWKS URI, use the async verify() method instead, it will download and parse the JWKS for you",
        ].join());
    }
    verifySignatureAgainstJwk(header, headerB64, payload, payloadB64, signatureB64, jwk, jwkToKeyObjectTransformer);
    try {
        (0, jwt_js_1.validateJwtFields)(payload, options);
        if (options.customJwtCheck) {
            const res = options.customJwtCheck({ header, payload, jwk });
            (0, assert_js_1.assertIsNotPromise)(res, () => new error_js_1.ParameterValidationError("Custom JWT checks must be synchronous but a promise was returned"));
        }
    }
    catch (err) {
        if (options.includeRawJwtInErrors && err instanceof error_js_1.JwtInvalidClaimError) {
            throw err.withRawJwt(decomposedJwt);
        }
        throw err;
    }
    return payload;
}
/**
 * Abstract class representing a verifier for JWTs signed with RSA (e.g. RS256, RS384, RS512)
 *
 * A class is used, because there is state:
 * - The JWKS is fetched (downloaded) from the JWKS URI and cached in memory
 * - Verification properties at verifier level, are used as default options for individual verify calls
 *
 * When instantiating this class, relevant type parameters should be provided, for your concrete case:
 * @param StillToProvide The verification options that you want callers of verify to provide on individual verify calls
 * @param SpecificVerifyProperties The verification options that you'll use
 * @param IssuerConfig The issuer config that you'll use (config options are used as default verification options)
 * @param MultiIssuer Verify multiple issuers (true) or just a single one (false)
 */
class JwtRsaVerifierBase {
    constructor(verifyProperties, jwksCache = new jwk_js_1.SimpleJwksCache()) {
        this.jwksCache = jwksCache;
        this.issuersConfig = new Map();
        this.publicKeyCache = new KeyObjectCache();
        if (Array.isArray(verifyProperties)) {
            if (!verifyProperties.length) {
                throw new error_js_1.ParameterValidationError("Provide at least one issuer configuration");
            }
            for (const prop of verifyProperties) {
                if (this.issuersConfig.has(prop.issuer)) {
                    throw new error_js_1.ParameterValidationError(`issuer ${prop.issuer} supplied multiple times`);
                }
                this.issuersConfig.set(prop.issuer, this.withJwksUri(prop));
            }
        }
        else {
            this.issuersConfig.set(verifyProperties.issuer, this.withJwksUri(verifyProperties));
        }
    }
    get expectedIssuers() {
        return Array.from(this.issuersConfig.keys());
    }
    getIssuerConfig(issuer) {
        if (!issuer) {
            if (this.issuersConfig.size !== 1) {
                throw new error_js_1.ParameterValidationError("issuer must be provided");
            }
            issuer = this.issuersConfig.keys().next().value;
        }
        const config = this.issuersConfig.get(issuer);
        if (!config) {
            throw new error_js_1.ParameterValidationError(`issuer not configured: ${issuer}`);
        }
        return config;
    }
    /**
     * This method loads a JWKS that you provide, into the JWKS cache, so that it is
     * available for JWT verification. Use this method to speed up the first JWT verification
     * (when the JWKS would otherwise have to be downloaded from the JWKS uri), or to provide the JWKS
     * in case the JwtVerifier does not have internet access to download the JWKS
     *
     * @param jwksThe JWKS
     * @param issuer The issuer for which you want to cache the JWKS
     *  Supply this field, if you instantiated the JwtVerifier with multiple issuers
     * @returns void
     */
    cacheJwks(...[jwks, issuer]) {
        const issuerConfig = this.getIssuerConfig(issuer);
        this.jwksCache.addJwks(issuerConfig.jwksUri, jwks);
        this.publicKeyCache.clearCache(issuerConfig.issuer);
    }
    /**
     * Hydrate the JWKS cache for (all of) the configured issuer(s).
     * This will fetch and cache the latest and greatest JWKS for concerned issuer(s).
     *
     * @param issuer The issuer to fetch the JWKS for
     * @returns void
     */
    async hydrate() {
        const jwksFetches = this.expectedIssuers
            .map((issuer) => this.getIssuerConfig(issuer).jwksUri)
            .map((jwksUri) => this.jwksCache.getJwks(jwksUri));
        await Promise.all(jwksFetches);
    }
    /**
     * Verify (synchronously) a JWT that is signed using RS256 / RS384 / RS512.
     *
     * @param jwt The JWT, as string
     * @param props Verification properties
     * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
     */
    verifySync(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        return this.verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties);
    }
    /**
     * Verify (synchronously) an already decomposed JWT, that is signed using RS256 / RS384 / RS512.
     *
     * @param decomposedJwt The decomposed Jwt
     * @param jwk The JWK to verify the JWTs signature with
     * @param verifyProperties The properties to use for verification
     * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
     */
    verifyDecomposedJwtSync(decomposedJwt, jwksUri, verifyProperties) {
        const jwk = this.jwksCache.getCachedJwk(jwksUri, decomposedJwt);
        return verifyDecomposedJwtSync(decomposedJwt, jwk, verifyProperties, this.publicKeyCache.transformJwkToKeyObject.bind(this.publicKeyCache));
    }
    /**
     * Verify (asynchronously) a JWT that is signed using RS256 / RS384 / RS512.
     * This call is asynchronous, and the JWKS will be fetched from the JWKS uri,
     * in case it is not yet available in the cache.
     *
     * @param jwt The JWT, as string
     * @param props Verification properties
     * @returns Promise that resolves to the payload of the JWT––if the JWT is valid, otherwise the promise rejects
     */
    async verify(...[jwt, properties]) {
        const { decomposedJwt, jwksUri, verifyProperties } = this.getVerifyParameters(jwt, properties);
        return this.verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties);
    }
    /**
     * Verify (asynchronously) an already decomposed JWT, that is signed using RS256 / RS384 / RS512.
     *
     * @param decomposedJwt The decomposed Jwt
     * @param jwk The JWK to verify the JWTs signature with
     * @param verifyProperties The properties to use for verification
     * @returns The payload of the JWT––if the JWT is valid, otherwise an error is thrown
     */
    verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties) {
        return verifyDecomposedJwt(decomposedJwt, jwksUri, verifyProperties, this.jwksCache.getJwk.bind(this.jwksCache), this.publicKeyCache.transformJwkToKeyObject.bind(this.publicKeyCache));
    }
    /**
     * Get the verification parameters to use, by merging the issuer configuration,
     * with the overriding properties that are now provided
     *
     * @param jwt: the JWT that is going to be verified
     * @param verifyProperties: the overriding properties, that override the issuer configuration
     * @returns The merged verification parameters
     */
    getVerifyParameters(jwt, verifyProperties) {
        const decomposedJwt = (0, jwt_js_1.decomposeJwt)(jwt);
        (0, assert_js_1.assertStringArrayContainsString)("Issuer", decomposedJwt.payload.iss, this.expectedIssuers, error_js_1.JwtInvalidIssuerError);
        const issuerConfig = this.getIssuerConfig(decomposedJwt.payload.iss);
        return {
            decomposedJwt,
            jwksUri: issuerConfig.jwksUri,
            verifyProperties: {
                ...issuerConfig,
                ...verifyProperties,
            },
        };
    }
    /**
     * Get issuer config with JWKS URI, by adding a default JWKS URI if needed
     *
     * @param config: the issuer config.
     * @returns The config with JWKS URI
     */
    withJwksUri(config) {
        if (config.jwksUri) {
            return config;
        }
        const issuerUri = new url_1.URL(config.issuer);
        return {
            jwksUri: new url_1.URL((0, path_1.join)(issuerUri.pathname, "/.well-known/jwks.json"), config.issuer).href,
            ...config,
        };
    }
}
exports.JwtRsaVerifierBase = JwtRsaVerifierBase;
/**
 * Class representing a verifier for JWTs signed with RSA (e.g. RS256 / RS384 / RS512)
 */
class JwtRsaVerifier extends JwtRsaVerifierBase {
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    static create(verifyProperties, additionalProperties) {
        return new this(verifyProperties, additionalProperties?.jwksCache);
    }
}
exports.JwtRsaVerifier = JwtRsaVerifier;
/**
 * Transform the JWK into an RSA public key in Node.js native key object format
 *
 * @param jwk: the JWK
 * @returns the RSA public key in Node.js native key object format
 */
const transformJwkToKeyObject = (jwk) => (0, crypto_1.createPublicKey)({
    key: (0, asn1_js_1.constructPublicKeyInDerFormat)(Buffer.from(jwk.n, "base64"), Buffer.from(jwk.e, "base64")),
    format: "der",
    type: "spki",
});
exports.transformJwkToKeyObject = transformJwkToKeyObject;
/**
 * Class representing a cache of RSA public keys in Node.js native key object format
 *
 * Because it takes a bit of compute time to turn a JWK into Node.js native key object format,
 * we want to cache this computation.
 */
class KeyObjectCache {
    constructor(jwkToKeyObjectTransformer = exports.transformJwkToKeyObject) {
        this.jwkToKeyObjectTransformer = jwkToKeyObjectTransformer;
        this.publicKeys = new Map();
    }
    /**
     * Transform the JWK into an RSA public key in Node.js native key object format.
     * If the transformed JWK is already in the cache, it is returned from the cache instead.
     * The cache keys are: issuer, JWK kid (key id)
     *
     * @param jwk: the JWK
     * @param issuer: the issuer that uses the JWK for signing JWTs
     * @returns the RSA public key in Node.js native key object format
     */
    transformJwkToKeyObject(jwk, issuer) {
        if (!issuer) {
            return this.jwkToKeyObjectTransformer(jwk);
        }
        const cachedPublicKey = this.publicKeys.get(issuer)?.get(jwk.kid);
        if (cachedPublicKey) {
            return cachedPublicKey;
        }
        const publicKey = this.jwkToKeyObjectTransformer(jwk);
        const cachedIssuer = this.publicKeys.get(issuer);
        if (cachedIssuer) {
            cachedIssuer.set(jwk.kid, publicKey);
        }
        else {
            this.publicKeys.set(issuer, new Map([[jwk.kid, publicKey]]));
        }
        return publicKey;
    }
    clearCache(issuer) {
        this.publicKeys.delete(issuer);
    }
}
exports.KeyObjectCache = KeyObjectCache;


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/jwt.js":
/*!*****************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/jwt.js ***!
  \*****************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.validateJwtFields = exports.decomposeJwt = void 0;
const assert_js_1 = __webpack_require__(/*! ./assert.js */ "./node_modules/aws-jwt-verify/dist/cjs/assert.js");
const safe_json_parse_js_1 = __webpack_require__(/*! ./safe-json-parse.js */ "./node_modules/aws-jwt-verify/dist/cjs/safe-json-parse.js");
const error_js_1 = __webpack_require__(/*! ./error.js */ "./node_modules/aws-jwt-verify/dist/cjs/error.js");
/**
 * Assert that the argument is a valid JWT header object.
 * Throws an error in case it is not.
 *
 * @param header
 * @returns void
 */
function assertJwtHeader(header) {
    if (!(0, safe_json_parse_js_1.isJsonObject)(header)) {
        throw new error_js_1.JwtParseError("JWT header is not an object");
    }
    if (header.alg !== undefined && typeof header.alg !== "string") {
        throw new error_js_1.JwtParseError("JWT header alg claim is not a string");
    }
    if (header.kid !== undefined && typeof header.kid !== "string") {
        throw new error_js_1.JwtParseError("JWT header kid claim is not a string");
    }
}
/**
 * Assert that the argument is a valid JWT payload object.
 * Throws an error in case it is not.
 *
 * @param payload
 * @returns void
 */
function assertJwtPayload(payload) {
    if (!(0, safe_json_parse_js_1.isJsonObject)(payload)) {
        throw new error_js_1.JwtParseError("JWT payload is not an object");
    }
    if (payload.exp !== undefined && !Number.isFinite(payload.exp)) {
        throw new error_js_1.JwtParseError("JWT payload exp claim is not a number");
    }
    if (payload.iss !== undefined && typeof payload.iss !== "string") {
        throw new error_js_1.JwtParseError("JWT payload iss claim is not a string");
    }
    if (payload.aud !== undefined &&
        typeof payload.aud !== "string" &&
        (!Array.isArray(payload.aud) ||
            payload.aud.some((aud) => typeof aud !== "string"))) {
        throw new error_js_1.JwtParseError("JWT payload aud claim is not a string or array of strings");
    }
    if (payload.nbf !== undefined && !Number.isFinite(payload.nbf)) {
        throw new error_js_1.JwtParseError("JWT payload nbf claim is not a number");
    }
    if (payload.iat !== undefined && !Number.isFinite(payload.iat)) {
        throw new error_js_1.JwtParseError("JWT payload iat claim is not a number");
    }
    if (payload.scope !== undefined && typeof payload.scope !== "string") {
        throw new error_js_1.JwtParseError("JWT payload scope claim is not a string");
    }
    if (payload.jti !== undefined && typeof payload.jti !== "string") {
        throw new error_js_1.JwtParseError("JWT payload jti claim is not a string");
    }
}
/**
 * Sanity check, decompose and JSON parse a JWT string into its constituent parts:
 * - header object
 * - payload object
 * - signature string
 *
 * @param jwt The JWT (as string)
 * @returns the decomposed JWT
 */
function decomposeJwt(jwt) {
    // Sanity checks on JWT
    if (!jwt) {
        throw new error_js_1.JwtParseError("Empty JWT");
    }
    if (typeof jwt !== "string") {
        throw new error_js_1.JwtParseError("JWT is not a string");
    }
    if (!jwt.match(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)) {
        throw new error_js_1.JwtParseError("JWT string does not consist of exactly 3 parts (header, payload, signature)");
    }
    const [headerB64, payloadB64, signatureB64] = jwt.split(".");
    // B64 decode header and payload
    const [headerString, payloadString] = [headerB64, payloadB64].map((b64) => Buffer.from(b64, "base64").toString("utf8"));
    // Parse header
    let header;
    try {
        header = (0, safe_json_parse_js_1.safeJsonParse)(headerString);
    }
    catch (err) {
        throw new error_js_1.JwtParseError("Invalid JWT. Header is not a valid JSON object", err);
    }
    assertJwtHeader(header);
    // parse payload
    let payload;
    try {
        payload = (0, safe_json_parse_js_1.safeJsonParse)(payloadString);
    }
    catch (err) {
        throw new error_js_1.JwtParseError("Invalid JWT. Payload is not a valid JSON object", err);
    }
    assertJwtPayload(payload);
    return {
        header,
        headerB64,
        payload,
        payloadB64,
        signatureB64,
    };
}
exports.decomposeJwt = decomposeJwt;
/**
 * Validate JWT payload fields. Throws an error in case there's any validation issue.
 *
 * @param payload The (JSON parsed) JWT payload
 * @param options The options to use during validation
 * @returns void
 */
function validateJwtFields(payload, options) {
    // Check expiry
    if (payload.exp !== undefined) {
        if (payload.exp + (options.graceSeconds ?? 0) < Date.now() / 1000) {
            throw new error_js_1.JwtExpiredError(`Token expired at ${new Date(payload.exp * 1000).toISOString()}`, payload.exp);
        }
    }
    // Check not before
    if (payload.nbf !== undefined) {
        if (payload.nbf - (options.graceSeconds ?? 0) > Date.now() / 1000) {
            throw new error_js_1.JwtNotBeforeError(`Token can't be used before ${new Date(payload.nbf * 1000).toISOString()}`, payload.nbf);
        }
    }
    // Check JWT issuer
    if (options.issuer !== null) {
        if (options.issuer === undefined) {
            throw new error_js_1.ParameterValidationError("issuer must be provided or set to null explicitly");
        }
        (0, assert_js_1.assertStringArrayContainsString)("Issuer", payload.iss, options.issuer, error_js_1.JwtInvalidIssuerError);
    }
    // Check audience
    if (options.audience !== null) {
        if (options.audience === undefined) {
            throw new error_js_1.ParameterValidationError("audience must be provided or set to null explicitly");
        }
        (0, assert_js_1.assertStringArraysOverlap)("Audience", payload.aud, options.audience, error_js_1.JwtInvalidAudienceError);
    }
    // Check scope
    if (options.scope != null) {
        (0, assert_js_1.assertStringArraysOverlap)("Scope", payload.scope?.split(" "), options.scope, error_js_1.JwtInvalidScopeError);
    }
}
exports.validateJwtFields = validateJwtFields;


/***/ }),

/***/ "./node_modules/aws-jwt-verify/dist/cjs/safe-json-parse.js":
/*!*****************************************************************!*\
  !*** ./node_modules/aws-jwt-verify/dist/cjs/safe-json-parse.js ***!
  \*****************************************************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Utility to parse JSON safely
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.safeJsonParse = exports.isJsonObject = void 0;
/**
 * Check if a piece of JSON is a JSON object, and not e.g. a mere string or null
 *
 * @param j - the JSON
 */
function isJsonObject(j) {
    // It is not enough to check that `typeof j === "object"`
    // because in JS `typeof null` is also "object", and so is `typeof []`.
    // So we need to check that j is an object, and not null, and not an array
    return typeof j === "object" && !Array.isArray(j) && j !== null;
}
exports.isJsonObject = isJsonObject;
/**
 * Parse a string as JSON, while removing __proto__ and constructor, so JS prototype pollution is prevented
 *
 * @param s - the string to JSON parse
 */
function safeJsonParse(s) {
    return JSON.parse(s, (_, value) => {
        if (typeof value === "object" && !Array.isArray(value) && value !== null) {
            delete value.__proto__;
            delete value.constructor;
        }
        return value;
    });
}
exports.safeJsonParse = safeJsonParse;


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __webpack_require__("./deploy/lambda/edge/index.ts");
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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QUNyQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsQ0FBQywwQkFBMEI7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7QUFDVjtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSw0Q0FBNEM7QUFDNUM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNB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QUFDTDtBQUNBLHFCQUFxQjs7Ozs7OztVQ2pDckI7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTs7VUFFQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTs7OztVRXRCQTtVQUNBO1VBQ0E7VUFDQSIsInNvdXJjZXMiOlsid2VicGFjazovL2NvZ25pdG8tc2FtcGxlLy4vbm9kZV9tb2R1bGVzL0BkYXpuL2xhbWJkYS1wb3dlcnRvb2xzLWNvcnJlbGF0aW9uLWlkcy9pbmRleC5qcyIsIndlYnBhY2s6Ly9jb2duaXRvLXNhbXBsZS8uL25vZGVfbW9kdWxlcy9AZGF6bi9sYW1iZGEtcG93ZXJ0b29scy1sb2dnZXIvaW5kZXguanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9kZXBsb3kvbGFtYmRhL2VkZ2UvaW5kZXgudHMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvZXh0ZXJuYWwgbm9kZS1jb21tb25qcyBcImNyeXB0b1wiIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlL2V4dGVybmFsIG5vZGUtY29tbW9uanMgXCJodHRwc1wiIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlL2V4dGVybmFsIG5vZGUtY29tbW9uanMgXCJwYXRoXCIiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvZXh0ZXJuYWwgbm9kZS1jb21tb25qcyBcInN0cmVhbVwiIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlL2V4dGVybmFsIG5vZGUtY29tbW9uanMgXCJ1cmxcIiIsIndlYnBhY2s6Ly9jb2duaXRvLXNhbXBsZS9leHRlcm5hbCBub2RlLWNvbW1vbmpzIFwidXRpbFwiIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlLy4vbm9kZV9tb2R1bGVzL2F3cy1qd3QtdmVyaWZ5L2Rpc3QvY2pzL2FzbjEuanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9ub2RlX21vZHVsZXMvYXdzLWp3dC12ZXJpZnkvZGlzdC9janMvYXNzZXJ0LmpzIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlLy4vbm9kZV9tb2R1bGVzL2F3cy1qd3QtdmVyaWZ5L2Rpc3QvY2pzL2NvZ25pdG8tdmVyaWZpZXIuanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9ub2RlX21vZHVsZXMvYXdzLWp3dC12ZXJpZnkvZGlzdC9janMvZXJyb3IuanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9ub2RlX21vZHVsZXMvYXdzLWp3dC12ZXJpZnkvZGlzdC9janMvaHR0cHMuanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9ub2RlX21vZHVsZXMvYXdzLWp3dC12ZXJpZnkvZGlzdC9janMvaW5kZXguanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9ub2RlX21vZHVsZXMvYXdzLWp3dC12ZXJpZnkvZGlzdC9janMvandrLmpzIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlLy4vbm9kZV9tb2R1bGVzL2F3cy1qd3QtdmVyaWZ5L2Rpc3QvY2pzL2p3dC1yc2EuanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9ub2RlX21vZHVsZXMvYXdzLWp3dC12ZXJpZnkvZGlzdC9janMvand0LmpzIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlLy4vbm9kZV9tb2R1bGVzL2F3cy1qd3QtdmVyaWZ5L2Rpc3QvY2pzL3NhZmUtanNvbi1wYXJzZS5qcyIsIndlYnBhY2s6Ly9jb2duaXRvLXNhbXBsZS93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9jb2duaXRvLXNhbXBsZS93ZWJwYWNrL2JlZm9yZS1zdGFydHVwIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlL3dlYnBhY2svc3RhcnR1cCIsIndlYnBhY2s6Ly9jb2duaXRvLXNhbXBsZS93ZWJwYWNrL2FmdGVyLXN0YXJ0dXAiXSwic291cmNlc0NvbnRlbnQiOlsiY29uc3QgREVCVUdfTE9HX0VOQUJMRUQgPSAnZGVidWctbG9nLWVuYWJsZWQnXG5cbmNsYXNzIENvcnJlbGF0aW9uSWRzIHtcbiAgY29uc3RydWN0b3IgKGNvbnRleHQgPSB7fSkge1xuICAgIHRoaXMuY29udGV4dCA9IGNvbnRleHRcbiAgfVxuXG4gIGNsZWFyQWxsICgpIHtcbiAgICB0aGlzLmNvbnRleHQgPSB7fVxuICB9XG5cbiAgcmVwbGFjZUFsbFdpdGggKGN0eCkge1xuICAgIHRoaXMuY29udGV4dCA9IGN0eFxuICB9XG5cbiAgc2V0IChrZXksIHZhbHVlKSB7XG4gICAgaWYgKCFrZXkuc3RhcnRzV2l0aCgneC1jb3JyZWxhdGlvbi0nKSkge1xuICAgICAga2V5ID0gJ3gtY29ycmVsYXRpb24tJyArIGtleVxuICAgIH1cblxuICAgIHRoaXMuY29udGV4dFtrZXldID0gdmFsdWVcbiAgfVxuXG4gIGdldCAoKSB7XG4gICAgcmV0dXJuIHRoaXMuY29udGV4dFxuICB9XG5cbiAgZ2V0IGRlYnVnTG9nZ2luZ0VuYWJsZWQgKCkge1xuICAgIHJldHVybiB0aGlzLmNvbnRleHRbREVCVUdfTE9HX0VOQUJMRURdID09PSAndHJ1ZSdcbiAgfVxuXG4gIHNldCBkZWJ1Z0xvZ2dpbmdFbmFibGVkIChlbmFibGVkKSB7XG4gICAgdGhpcy5jb250ZXh0W0RFQlVHX0xPR19FTkFCTEVEXSA9IGVuYWJsZWQgPyAndHJ1ZScgOiAnZmFsc2UnXG4gIH1cblxuICBzdGF0aWMgY2xlYXJBbGwgKCkge1xuICAgIGdsb2JhbENvcnJlbGF0aW9uSWRzLmNsZWFyQWxsKClcbiAgfVxuXG4gIHN0YXRpYyByZXBsYWNlQWxsV2l0aCAoLi4uYXJncykge1xuICAgIGdsb2JhbENvcnJlbGF0aW9uSWRzLnJlcGxhY2VBbGxXaXRoKC4uLmFyZ3MpXG4gIH1cblxuICBzdGF0aWMgc2V0ICguLi5hcmdzKSB7XG4gICAgZ2xvYmFsQ29ycmVsYXRpb25JZHMuc2V0KC4uLmFyZ3MpXG4gIH1cblxuICBzdGF0aWMgZ2V0ICgpIHtcbiAgICByZXR1cm4gZ2xvYmFsQ29ycmVsYXRpb25JZHMuZ2V0KClcbiAgfVxuXG4gIHN0YXRpYyBnZXQgZGVidWdMb2dnaW5nRW5hYmxlZCAoKSB7XG4gICAgcmV0dXJuIGdsb2JhbENvcnJlbGF0aW9uSWRzLmRlYnVnTG9nZ2luZ0VuYWJsZWRcbiAgfVxuXG4gIHN0YXRpYyBzZXQgZGVidWdMb2dnaW5nRW5hYmxlZCAoZW5hYmxlZCkge1xuICAgIGdsb2JhbENvcnJlbGF0aW9uSWRzLmRlYnVnTG9nZ2luZ0VuYWJsZWQgPSBlbmFibGVkXG4gIH1cbn1cblxuaWYgKCFnbG9iYWwuQ09SUkVMQVRJT05fSURTKSB7XG4gIGdsb2JhbC5DT1JSRUxBVElPTl9JRFMgPSBuZXcgQ29ycmVsYXRpb25JZHMoKVxufVxuXG5jb25zdCBnbG9iYWxDb3JyZWxhdGlvbklkcyA9IGdsb2JhbC5DT1JSRUxBVElPTl9JRFNcblxubW9kdWxlLmV4cG9ydHMgPSBDb3JyZWxhdGlvbklkc1xuIiwiY29uc3QgQ29ycmVsYXRpb25JZHMgPSByZXF1aXJlKCdAZGF6bi9sYW1iZGEtcG93ZXJ0b29scy1jb3JyZWxhdGlvbi1pZHMnKVxuXG4vLyBMZXZlbHMgaGVyZSBhcmUgaWRlbnRpY2FsIHRvIGJ1bnlhbiBwcmFjdGljZXNcbi8vIGh0dHBzOi8vZ2l0aHViLmNvbS90cmVudG0vbm9kZS1idW55YW4jbGV2ZWxzXG5jb25zdCBMb2dMZXZlbHMgPSB7XG4gIERFQlVHOiAyMCxcbiAgSU5GTzogMzAsXG4gIFdBUk46IDQwLFxuICBFUlJPUjogNTBcbn1cblxuLy8gbW9zdCBvZiB0aGVzZSBhcmUgYXZhaWxhYmxlIHRocm91Z2ggdGhlIE5vZGUuanMgZXhlY3V0aW9uIGVudmlyb25tZW50IGZvciBMYW1iZGFcbi8vIHNlZSBodHRwczovL2RvY3MuYXdzLmFtYXpvbi5jb20vbGFtYmRhL2xhdGVzdC9kZy9jdXJyZW50LXN1cHBvcnRlZC12ZXJzaW9ucy5odG1sXG5jb25zdCBERUZBVUxUX0NPTlRFWFQgPSB7XG4gIGF3c1JlZ2lvbjogcHJvY2Vzcy5lbnYuQVdTX1JFR0lPTiB8fCBwcm9jZXNzLmVudi5BV1NfREVGQVVMVF9SRUdJT04sXG4gIGZ1bmN0aW9uTmFtZTogcHJvY2Vzcy5lbnYuQVdTX0xBTUJEQV9GVU5DVElPTl9OQU1FLFxuICBmdW5jdGlvblZlcnNpb246IHByb2Nlc3MuZW52LkFXU19MQU1CREFfRlVOQ1RJT05fVkVSU0lPTixcbiAgZnVuY3Rpb25NZW1vcnlTaXplOiBwcm9jZXNzLmVudi5BV1NfTEFNQkRBX0ZVTkNUSU9OX01FTU9SWV9TSVpFLFxuICBlbnZpcm9ubWVudDogcHJvY2Vzcy5lbnYuRU5WSVJPTk1FTlQgfHwgcHJvY2Vzcy5lbnYuU1RBR0UgLy8gY29udmVudGlvbiBpbiBvdXIgZnVuY3Rpb25zXG59XG5cbmNsYXNzIExvZ2dlciB7XG4gIGNvbnN0cnVjdG9yICh7XG4gICAgY29ycmVsYXRpb25JZHMgPSBDb3JyZWxhdGlvbklkcyxcbiAgICBsZXZlbCA9IHByb2Nlc3MuZW52LkxPR19MRVZFTFxuICB9ID0ge30pIHtcbiAgICB0aGlzLmNvcnJlbGF0aW9uSWRzID0gY29ycmVsYXRpb25JZHNcbiAgICB0aGlzLmxldmVsID0gKGxldmVsIHx8ICdERUJVRycpLnRvVXBwZXJDYXNlKClcbiAgICB0aGlzLm9yaWdpbmFsTGV2ZWwgPSB0aGlzLmxldmVsXG5cbiAgICBpZiAoY29ycmVsYXRpb25JZHMuZGVidWdFbmFibGVkKSB7XG4gICAgICB0aGlzLmVuYWJsZURlYnVnKClcbiAgICB9XG4gIH1cblxuICBnZXQgY29udGV4dCAoKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIC4uLkRFRkFVTFRfQ09OVEVYVCxcbiAgICAgIC4uLnRoaXMuY29ycmVsYXRpb25JZHMuZ2V0KClcbiAgICB9XG4gIH1cblxuICBpc0VuYWJsZWQgKGxldmVsKSB7XG4gICAgcmV0dXJuIGxldmVsID49IChMb2dMZXZlbHNbdGhpcy5sZXZlbF0gfHwgTG9nTGV2ZWxzLkRFQlVHKVxuICB9XG5cbiAgYXBwZW5kRXJyb3IgKHBhcmFtcywgZXJyKSB7XG4gICAgaWYgKCFlcnIpIHtcbiAgICAgIHJldHVybiBwYXJhbXNcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgLi4ucGFyYW1zIHx8IHt9LFxuICAgICAgZXJyb3JOYW1lOiBlcnIubmFtZSxcbiAgICAgIGVycm9yTWVzc2FnZTogZXJyLm1lc3NhZ2UsXG4gICAgICBzdGFja1RyYWNlOiBlcnIuc3RhY2tcbiAgICB9XG4gIH1cblxuICBsb2cgKGxldmVsTmFtZSwgbWVzc2FnZSwgcGFyYW1zKSB7XG4gICAgY29uc3QgbGV2ZWwgPSBMb2dMZXZlbHNbbGV2ZWxOYW1lXVxuICAgIGlmICghdGhpcy5pc0VuYWJsZWQobGV2ZWwpKSB7XG4gICAgICByZXR1cm5cbiAgICB9XG5cbiAgICBjb25zdCBsb2dNc2cgPSB7XG4gICAgICAuLi50aGlzLmNvbnRleHQsXG4gICAgICAuLi5wYXJhbXMsXG4gICAgICBsZXZlbCxcbiAgICAgIHNMZXZlbDogbGV2ZWxOYW1lLFxuICAgICAgbWVzc2FnZVxuICAgIH1cblxuICAgIGNvbnN0IGNvbnNvbGVNZXRob2RzID0ge1xuICAgICAgREVCVUc6IGNvbnNvbGUuZGVidWcsXG4gICAgICBJTkZPOiBjb25zb2xlLmluZm8sXG4gICAgICBXQVJOOiBjb25zb2xlLndhcm4sXG4gICAgICBFUlJPUjogY29uc29sZS5lcnJvclxuICAgIH1cblxuICAgIC8vIHJlLW9yZGVyIG1lc3NhZ2UgYW5kIHBhcmFtcyB0byBhcHBlYXIgZWFybGllciBpbiB0aGUgbG9nIHJvd1xuICAgIGNvbnNvbGVNZXRob2RzW2xldmVsTmFtZV0oSlNPTi5zdHJpbmdpZnkoeyBtZXNzYWdlLCAuLi5wYXJhbXMsIC4uLmxvZ01zZyB9LCAoa2V5LCB2YWx1ZSkgPT4gdHlwZW9mIHZhbHVlID09PSAnYmlnaW50J1xuICAgICAgPyB2YWx1ZS50b1N0cmluZygpXG4gICAgICA6IHZhbHVlXG4gICAgKSlcbiAgfVxuXG4gIGRlYnVnIChtc2csIHBhcmFtcykge1xuICAgIHRoaXMubG9nKCdERUJVRycsIG1zZywgcGFyYW1zKVxuICB9XG5cbiAgaW5mbyAobXNnLCBwYXJhbXMpIHtcbiAgICB0aGlzLmxvZygnSU5GTycsIG1zZywgcGFyYW1zKVxuICB9XG5cbiAgd2FybiAobXNnLCBwYXJhbXMsIGVycikge1xuICAgIGNvbnN0IHBhcmFtZXRlcnMgPSAhZXJyICYmIHBhcmFtcyBpbnN0YW5jZW9mIEVycm9yID8gdGhpcy5hcHBlbmRFcnJvcih7fSwgcGFyYW1zKSA6IHRoaXMuYXBwZW5kRXJyb3IocGFyYW1zLCBlcnIpXG4gICAgdGhpcy5sb2coJ1dBUk4nLCBtc2csIHBhcmFtZXRlcnMpXG4gIH1cblxuICBlcnJvciAobXNnLCBwYXJhbXMsIGVycikge1xuICAgIGNvbnN0IHBhcmFtZXRlcnMgPSAhZXJyICYmIHBhcmFtcyBpbnN0YW5jZW9mIEVycm9yID8gdGhpcy5hcHBlbmRFcnJvcih7fSwgcGFyYW1zKSA6IHRoaXMuYXBwZW5kRXJyb3IocGFyYW1zLCBlcnIpXG4gICAgdGhpcy5sb2coJ0VSUk9SJywgbXNnLCBwYXJhbWV0ZXJzKVxuICB9XG5cbiAgZW5hYmxlRGVidWcgKCkge1xuICAgIHRoaXMubGV2ZWwgPSAnREVCVUcnXG4gICAgcmV0dXJuICgpID0+IHRoaXMucmVzZXRMZXZlbCgpXG4gIH1cblxuICByZXNldExldmVsICgpIHtcbiAgICB0aGlzLmxldmVsID0gdGhpcy5vcmlnaW5hbExldmVsXG4gIH1cblxuICBzdGF0aWMgZGVidWcgKC4uLmFyZ3MpIHtcbiAgICBnbG9iYWxMb2dnZXIuZGVidWcoLi4uYXJncylcbiAgfVxuXG4gIHN0YXRpYyBpbmZvICguLi5hcmdzKSB7XG4gICAgZ2xvYmFsTG9nZ2VyLmluZm8oLi4uYXJncylcbiAgfVxuXG4gIHN0YXRpYyB3YXJuICguLi5hcmdzKSB7XG4gICAgZ2xvYmFsTG9nZ2VyLndhcm4oLi4uYXJncylcbiAgfVxuXG4gIHN0YXRpYyBlcnJvciAoLi4uYXJncykge1xuICAgIGdsb2JhbExvZ2dlci5lcnJvciguLi5hcmdzKVxuICB9XG5cbiAgc3RhdGljIGVuYWJsZURlYnVnICgpIHtcbiAgICByZXR1cm4gZ2xvYmFsTG9nZ2VyLmVuYWJsZURlYnVnKClcbiAgfVxuXG4gIHN0YXRpYyByZXNldExldmVsICgpIHtcbiAgICBnbG9iYWxMb2dnZXIucmVzZXRMZXZlbCgpXG4gIH1cblxuICBzdGF0aWMgZ2V0IGxldmVsICgpIHtcbiAgICByZXR1cm4gZ2xvYmFsTG9nZ2VyLmxldmVsXG4gIH1cbn1cblxuY29uc3QgZ2xvYmFsTG9nZ2VyID0gbmV3IExvZ2dlcigpXG5cbm1vZHVsZS5leHBvcnRzID0gTG9nZ2VyXG4iLCJpbXBvcnQgTG9nIGZyb20gJ0BkYXpuL2xhbWJkYS1wb3dlcnRvb2xzLWxvZ2dlcidcbmltcG9ydCB7IENvZ25pdG9Kd3RWZXJpZmllciB9IGZyb20gJ2F3cy1qd3QtdmVyaWZ5J1xuaW1wb3J0IHsgQ2xvdWRGcm9udFJlcXVlc3RIYW5kbGVyIH0gZnJvbSAnYXdzLWxhbWJkYSdcblxuZXhwb3J0IGNvbnN0IGhhbmRsZXI6IENsb3VkRnJvbnRSZXF1ZXN0SGFuZGxlciA9IGFzeW5jIChldmVudCwgY29udGV4dCwgY2FsbGJhY2spID0+IHtcbiAgTG9nLmluZm8oJ1N0YXJ0IEF1dGgnKVxuICBjb25zdCB1c2VyUG9vbElkID0gcHJvY2Vzcy5lbnYuVVNFUl9QT09MX0lEID8gcHJvY2Vzcy5lbnYuVVNFUl9QT09MX0lEIDogJydcbiAgY29uc3QgdG9rZW5Vc2UgPSAnaWQnXG4gIGNvbnN0IGNsaWVudElkID0gcHJvY2Vzcy5lbnYuQ0xJRU5UX0lEID8gcHJvY2Vzcy5lbnYuQ0xJRU5UX0lEIDogJydcblxuICBjb25zdCB2ZXJpZmllciA9IENvZ25pdG9Kd3RWZXJpZmllci5jcmVhdGUoe1xuICAgIHVzZXJQb29sSWQsXG4gICAgdG9rZW5Vc2UsXG4gICAgY2xpZW50SWQsXG4gIH0pXG5cbiAgY29uc3QgcmVxdWVzdCA9IGV2ZW50LlJlY29yZHNbMF0uY2YucmVxdWVzdFxuXG4gIExvZy5pbmZvKCdoZWFkZXJzJywgcmVxdWVzdClcbiAgZm9yIChjb25zdCBjb29raWUgb2YgcmVxdWVzdC5oZWFkZXJzWydjb29raWUnXSkge1xuICAgIGlmIChjb29raWUua2V5ID09PSAnY29va2llJykge1xuICAgICAgLy8g6KqN6Ki8T0tcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGNvb2tpZXMgPSBjb29raWUudmFsdWUuc3BsaXQoJzsnKVxuICAgICAgICBmb3IgKGNvbnN0IGMgb2YgY29va2llcykge1xuICAgICAgICAgIGlmIChjLnNwbGl0KCdpZFRva2VuPScpWzFdKSB7XG4gICAgICAgICAgICBMb2cuaW5mbyhjLnNwbGl0KCdpZFRva2VuPScpWzFdKVxuICAgICAgICAgICAgY29uc3QgcGF5bG9hZCA9IGF3YWl0IHZlcmlmaWVyLnZlcmlmeShjLnNwbGl0KCdpZFRva2VuPScpWzFdKVxuICAgICAgICAgICAgTG9nLmluZm8oJ1Rva2VuIGlzIHZhbGlkLiBQYXlsb2FkOicsIHBheWxvYWQpXG4gICAgICAgICAgICBjYWxsYmFjayhudWxsLCByZXF1ZXN0KVxuICAgICAgICAgICAgcmV0dXJuIG51bGxcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH0gY2F0Y2gge1xuICAgICAgICBMb2cuaW5mbygnVG9rZW4gbm90IHZhbGlkIScpXG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLy8g6KqN6Ki8TkdcbiAgY2FsbGJhY2sobnVsbCwge1xuICAgIHN0YXR1czogJzQwMScsXG4gICAgc3RhdHVzRGVzY3JpcHRpb246ICdVbmF1dGhvcml6ZWQnLFxuICAgIGJvZHk6ICc8aDE+NDAxIFVuYXV0aG9yaXplZDwvaDE+JyxcbiAgfSlcbn1cbiIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImNyeXB0b1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJodHRwc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJwYXRoXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInN0cmVhbVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJ1cmxcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwidXRpbFwiKTsiLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCBBbWF6b24uY29tLCBJbmMuIG9yIGl0cyBhZmZpbGlhdGVzLiBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IEFwYWNoZS0yLjBcbi8vXG4vLyBVdGlsaXR5IHRvIGVuY29kZSBSU0EgcHVibGljIGtleXMgKGEgcGFpciBvZiBtb2R1bHVzIChuKSBhbmQgZXhwb25lbnQgKGUpKSBpbnRvIERFUi1lbmNvZGluZywgcGVyIEFTTi4xIHNwZWNpZmljYXRpb24uXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG5leHBvcnRzLmRlY29uc3RydWN0UHVibGljS2V5SW5EZXJGb3JtYXQgPSBleHBvcnRzLmNvbnN0cnVjdFB1YmxpY0tleUluRGVyRm9ybWF0ID0gdm9pZCAwO1xuY29uc3QgZXJyb3JfanNfMSA9IHJlcXVpcmUoXCIuL2Vycm9yLmpzXCIpO1xuLyoqIEVudW0gd2l0aCBwb3NzaWJsZSB2YWx1ZXMgZm9yIHN1cHBvcnRlZCBBU04uMSBjbGFzc2VzICovXG52YXIgQXNuMUNsYXNzO1xuKGZ1bmN0aW9uIChBc24xQ2xhc3MpIHtcbiAgICBBc24xQ2xhc3NbQXNuMUNsYXNzW1wiVW5pdmVyc2FsXCJdID0gMF0gPSBcIlVuaXZlcnNhbFwiO1xufSkoQXNuMUNsYXNzIHx8IChBc24xQ2xhc3MgPSB7fSkpO1xuLyoqIEVudW0gd2l0aCBwb3NzaWJsZSB2YWx1ZXMgZm9yIHN1cHBvcnRlZCBBU04uMSBlbmNvZGluZ3MgKi9cbnZhciBBc24xRW5jb2Rpbmc7XG4oZnVuY3Rpb24gKEFzbjFFbmNvZGluZykge1xuICAgIEFzbjFFbmNvZGluZ1tBc24xRW5jb2RpbmdbXCJQcmltaXRpdmVcIl0gPSAwXSA9IFwiUHJpbWl0aXZlXCI7XG4gICAgQXNuMUVuY29kaW5nW0FzbjFFbmNvZGluZ1tcIkNvbnN0cnVjdGVkXCJdID0gMV0gPSBcIkNvbnN0cnVjdGVkXCI7XG59KShBc24xRW5jb2RpbmcgfHwgKEFzbjFFbmNvZGluZyA9IHt9KSk7XG4vKiogRW51bSB3aXRoIHBvc3NpYmxlIHZhbHVlcyBmb3Igc3VwcG9ydGVkIEFTTi4xIHRhZ3MgKi9cbnZhciBBc24xVGFnO1xuKGZ1bmN0aW9uIChBc24xVGFnKSB7XG4gICAgQXNuMVRhZ1tBc24xVGFnW1wiQml0U3RyaW5nXCJdID0gM10gPSBcIkJpdFN0cmluZ1wiO1xuICAgIEFzbjFUYWdbQXNuMVRhZ1tcIk9iamVjdElkZW50aWZpZXJcIl0gPSA2XSA9IFwiT2JqZWN0SWRlbnRpZmllclwiO1xuICAgIEFzbjFUYWdbQXNuMVRhZ1tcIlNlcXVlbmNlXCJdID0gMTZdID0gXCJTZXF1ZW5jZVwiO1xuICAgIEFzbjFUYWdbQXNuMVRhZ1tcIk51bGxcIl0gPSA1XSA9IFwiTnVsbFwiO1xuICAgIEFzbjFUYWdbQXNuMVRhZ1tcIkludGVnZXJcIl0gPSAyXSA9IFwiSW50ZWdlclwiO1xufSkoQXNuMVRhZyB8fCAoQXNuMVRhZyA9IHt9KSk7XG4vKipcbiAqIEVuY29kZSBhbiBBU04uMSBpZGVudGlmaWVyIHBlciBBU04uMSBzcGVjIChERVItZW5jb2RpbmcpXG4gKiBTZWUgaHR0cHM6Ly93d3cuaXR1LmludC9JVFUtVC9zdHVkeWdyb3Vwcy9jb20xNy9sYW5ndWFnZXMvWC42OTAtMDIwNy5wZGYgY2hhcHRlciA4LjEuMlxuICpcbiAqIEBwYXJhbSBpZGVudGlmaWVyIC0gVGhlIEFTTi4xIGlkZW50aWZpZXJcbiAqIEByZXR1cm5zIFRoZSBidWZmZXJcbiAqL1xuZnVuY3Rpb24gZW5jb2RlSWRlbnRpZmllcihpZGVudGlmaWVyKSB7XG4gICAgY29uc3QgaWRlbnRpZmllckFzTnVtYmVyID0gKGlkZW50aWZpZXIuY2xhc3MgPDwgNykgfFxuICAgICAgICAoaWRlbnRpZmllci5wcmltaXRpdmVPckNvbnN0cnVjdGVkIDw8IDUpIHxcbiAgICAgICAgaWRlbnRpZmllci50YWc7XG4gICAgcmV0dXJuIEJ1ZmZlci5mcm9tKFtpZGVudGlmaWVyQXNOdW1iZXJdKTtcbn1cbi8qKlxuICogRW5jb2RlIHRoZSBsZW5ndGggb2YgYW4gQVNOLjEgdHlwZSBwZXIgQVNOLjEgc3BlYyAoREVSLWVuY29kaW5nKVxuICogU2VlIGh0dHBzOi8vd3d3Lml0dS5pbnQvSVRVLVQvc3R1ZHlncm91cHMvY29tMTcvbGFuZ3VhZ2VzL1guNjkwLTAyMDcucGRmIGNoYXB0ZXIgOC4xLjNcbiAqXG4gKiBAcGFyYW0gbGVuZ3RoIC0gVGhlIGxlbmd0aCBvZiB0aGUgQVNOLjEgdHlwZVxuICogQHJldHVybnMgVGhlIGJ1ZmZlclxuICovXG5mdW5jdGlvbiBlbmNvZGVMZW5ndGgobGVuZ3RoKSB7XG4gICAgaWYgKGxlbmd0aCA8IDEyOCkge1xuICAgICAgICByZXR1cm4gQnVmZmVyLmZyb20oW2xlbmd0aF0pO1xuICAgIH1cbiAgICBjb25zdCBpbnRlZ2VycyA9IFtdO1xuICAgIHdoaWxlIChsZW5ndGggPiAwKSB7XG4gICAgICAgIGludGVnZXJzLnB1c2gobGVuZ3RoICUgMjU2KTtcbiAgICAgICAgbGVuZ3RoID0gbGVuZ3RoID4+IDg7XG4gICAgfVxuICAgIGludGVnZXJzLnJldmVyc2UoKTtcbiAgICByZXR1cm4gQnVmZmVyLmZyb20oWzEyOCB8IGludGVnZXJzLmxlbmd0aCwgLi4uaW50ZWdlcnNdKTtcbn1cbi8qKlxuICogRW5jb2RlIGEgYnVmZmVyICh0aGF0IHJlcHJlc2VudCBhbiBpbnRlZ2VyKSBhcyBpbnRlZ2VyIHBlciBBU04uMSBzcGVjIChERVItZW5jb2RpbmcpXG4gKiBTZWUgaHR0cHM6Ly93d3cuaXR1LmludC9JVFUtVC9zdHVkeWdyb3Vwcy9jb20xNy9sYW5ndWFnZXMvWC42OTAtMDIwNy5wZGYgY2hhcHRlciA4LjNcbiAqXG4gKiBAcGFyYW0gYnVmZmVyIC0gVGhlIGJ1ZmZlciB0aGF0IHJlcHJlc2VudCBhbiBpbnRlZ2VyIHRvIGVuY29kZVxuICogQHJldHVybnMgVGhlIGJ1ZmZlclxuICovXG5mdW5jdGlvbiBlbmNvZGVCdWZmZXJBc0ludGVnZXIoYnVmZmVyKSB7XG4gICAgcmV0dXJuIEJ1ZmZlci5jb25jYXQoW1xuICAgICAgICBlbmNvZGVJZGVudGlmaWVyKHtcbiAgICAgICAgICAgIGNsYXNzOiBBc24xQ2xhc3MuVW5pdmVyc2FsLFxuICAgICAgICAgICAgcHJpbWl0aXZlT3JDb25zdHJ1Y3RlZDogQXNuMUVuY29kaW5nLlByaW1pdGl2ZSxcbiAgICAgICAgICAgIHRhZzogQXNuMVRhZy5JbnRlZ2VyLFxuICAgICAgICB9KSxcbiAgICAgICAgZW5jb2RlTGVuZ3RoKGJ1ZmZlci5sZW5ndGgpLFxuICAgICAgICBidWZmZXIsXG4gICAgXSk7XG59XG4vKipcbiAqIEVuY29kZSBhbiBvYmplY3QgaWRlbnRpZmllciAoYSBzdHJpbmcgc3VjaCBhcyBcIjEuMi44NDAuMTEzNTQ5LjEuMS4xXCIpIHBlciBBU04uMSBzcGVjIChERVItZW5jb2RpbmcpXG4gKiBTZWUgaHR0cHM6Ly93d3cuaXR1LmludC9JVFUtVC9zdHVkeWdyb3Vwcy9jb20xNy9sYW5ndWFnZXMvWC42OTAtMDIwNy5wZGYgY2hhcHRlciA4LjE5XG4gKlxuICogQHBhcmFtIG9pZCAtIFRoZSBvYmplY3QgaWRlbnRpZmllciB0byBlbmNvZGVcbiAqIEByZXR1cm5zIFRoZSBidWZmZXJcbiAqL1xuZnVuY3Rpb24gZW5jb2RlT2JqZWN0SWRlbnRpZmllcihvaWQpIHtcbiAgICBjb25zdCBvaWRDb21wb25lbnRzID0gb2lkLnNwbGl0KFwiLlwiKS5tYXAoKGkpID0+IHBhcnNlSW50KGkpKTtcbiAgICBjb25zdCBmaXJzdFN1YmlkZW50aWZpZXIgPSBvaWRDb21wb25lbnRzWzBdICogNDAgKyBvaWRDb21wb25lbnRzWzFdO1xuICAgIGNvbnN0IHN1YnNlcXVlbnRTdWJpZGVudGlmaWVycyA9IG9pZENvbXBvbmVudHNcbiAgICAgICAgLnNsaWNlKDIpXG4gICAgICAgIC5yZWR1Y2UoKGV4cGFuZGVkLCBjb21wb25lbnQpID0+IHtcbiAgICAgICAgY29uc3QgYnl0ZXMgPSBbXTtcbiAgICAgICAgZG8ge1xuICAgICAgICAgICAgYnl0ZXMucHVzaChjb21wb25lbnQgJSAxMjgpO1xuICAgICAgICAgICAgY29tcG9uZW50ID0gY29tcG9uZW50ID4+IDc7XG4gICAgICAgIH0gd2hpbGUgKGNvbXBvbmVudCk7XG4gICAgICAgIHJldHVybiBleHBhbmRlZC5jb25jYXQoYnl0ZXMubWFwKChiLCBpbmRleCkgPT4gKGluZGV4ID8gYiArIDEyOCA6IGIpKS5yZXZlcnNlKCkpO1xuICAgIH0sIFtdKTtcbiAgICBjb25zdCBvaWRCdWZmZXIgPSBCdWZmZXIuZnJvbShbXG4gICAgICAgIGZpcnN0U3ViaWRlbnRpZmllcixcbiAgICAgICAgLi4uc3Vic2VxdWVudFN1YmlkZW50aWZpZXJzLFxuICAgIF0pO1xuICAgIHJldHVybiBCdWZmZXIuY29uY2F0KFtcbiAgICAgICAgZW5jb2RlSWRlbnRpZmllcih7XG4gICAgICAgICAgICBjbGFzczogQXNuMUNsYXNzLlVuaXZlcnNhbCxcbiAgICAgICAgICAgIHByaW1pdGl2ZU9yQ29uc3RydWN0ZWQ6IEFzbjFFbmNvZGluZy5QcmltaXRpdmUsXG4gICAgICAgICAgICB0YWc6IEFzbjFUYWcuT2JqZWN0SWRlbnRpZmllcixcbiAgICAgICAgfSksXG4gICAgICAgIGVuY29kZUxlbmd0aChvaWRCdWZmZXIubGVuZ3RoKSxcbiAgICAgICAgb2lkQnVmZmVyLFxuICAgIF0pO1xufVxuLyoqXG4gKiBFbmNvZGUgYSBidWZmZXIgYXMgYml0IHN0cmluZyBwZXIgQVNOLjEgc3BlYyAoREVSLWVuY29kaW5nKVxuICogU2VlIGh0dHBzOi8vd3d3Lml0dS5pbnQvSVRVLVQvc3R1ZHlncm91cHMvY29tMTcvbGFuZ3VhZ2VzL1guNjkwLTAyMDcucGRmIGNoYXB0ZXIgOC42XG4gKlxuICogQHBhcmFtIGJ1ZmZlciAtIFRoZSBidWZmZXIgdG8gZW5jb2RlXG4gKiBAcmV0dXJucyBUaGUgYnVmZmVyXG4gKi9cbmZ1bmN0aW9uIGVuY29kZUJ1ZmZlckFzQml0U3RyaW5nKGJ1ZmZlcikge1xuICAgIGNvbnN0IGJpdFN0cmluZyA9IEJ1ZmZlci5jb25jYXQoW0J1ZmZlci5mcm9tKFswXSksIGJ1ZmZlcl0pO1xuICAgIHJldHVybiBCdWZmZXIuY29uY2F0KFtcbiAgICAgICAgZW5jb2RlSWRlbnRpZmllcih7XG4gICAgICAgICAgICBjbGFzczogQXNuMUNsYXNzLlVuaXZlcnNhbCxcbiAgICAgICAgICAgIHByaW1pdGl2ZU9yQ29uc3RydWN0ZWQ6IEFzbjFFbmNvZGluZy5QcmltaXRpdmUsXG4gICAgICAgICAgICB0YWc6IEFzbjFUYWcuQml0U3RyaW5nLFxuICAgICAgICB9KSxcbiAgICAgICAgZW5jb2RlTGVuZ3RoKGJpdFN0cmluZy5sZW5ndGgpLFxuICAgICAgICBiaXRTdHJpbmcsXG4gICAgXSk7XG59XG4vKipcbiAqIEVuY29kZSBhIHNlcXVlbmNlIG9mIERFUi1lbmNvZGVkIGl0ZW1zIHBlciBBU04uMSBzcGVjIChERVItZW5jb2RpbmcpXG4gKiBTZWUgaHR0cHM6Ly93d3cuaXR1LmludC9JVFUtVC9zdHVkeWdyb3Vwcy9jb20xNy9sYW5ndWFnZXMvWC42OTAtMDIwNy5wZGYgY2hhcHRlciA4LjlcbiAqXG4gKiBAcGFyYW0gc2VxdWVuY2VJdGVtcyAtIFRoZSBzZXF1ZW5jZSBvZiBERVItZW5jb2RlZCBpdGVtc1xuICogQHJldHVybnMgVGhlIGJ1ZmZlclxuICovXG5mdW5jdGlvbiBlbmNvZGVTZXF1ZW5jZShzZXF1ZW5jZUl0ZW1zKSB7XG4gICAgY29uc3QgY29uY2F0ZW5hdGVkID0gQnVmZmVyLmNvbmNhdChzZXF1ZW5jZUl0ZW1zKTtcbiAgICByZXR1cm4gQnVmZmVyLmNvbmNhdChbXG4gICAgICAgIGVuY29kZUlkZW50aWZpZXIoe1xuICAgICAgICAgICAgY2xhc3M6IEFzbjFDbGFzcy5Vbml2ZXJzYWwsXG4gICAgICAgICAgICBwcmltaXRpdmVPckNvbnN0cnVjdGVkOiBBc24xRW5jb2RpbmcuQ29uc3RydWN0ZWQsXG4gICAgICAgICAgICB0YWc6IEFzbjFUYWcuU2VxdWVuY2UsXG4gICAgICAgIH0pLFxuICAgICAgICBlbmNvZGVMZW5ndGgoY29uY2F0ZW5hdGVkLmxlbmd0aCksXG4gICAgICAgIGNvbmNhdGVuYXRlZCxcbiAgICBdKTtcbn1cbi8qKlxuICogRW5jb2RlIG51bGwgcGVyIEFTTi4xIHNwZWMgKERFUi1lbmNvZGluZylcbiAqIFNlZSBodHRwczovL3d3dy5pdHUuaW50L0lUVS1UL3N0dWR5Z3JvdXBzL2NvbTE3L2xhbmd1YWdlcy9YLjY5MC0wMjA3LnBkZiBjaGFwdGVyIDguOFxuICpcbiAqIEByZXR1cm5zIFRoZSBidWZmZXJcbiAqL1xuZnVuY3Rpb24gZW5jb2RlTnVsbCgpIHtcbiAgICByZXR1cm4gQnVmZmVyLmNvbmNhdChbXG4gICAgICAgIGVuY29kZUlkZW50aWZpZXIoe1xuICAgICAgICAgICAgY2xhc3M6IEFzbjFDbGFzcy5Vbml2ZXJzYWwsXG4gICAgICAgICAgICBwcmltaXRpdmVPckNvbnN0cnVjdGVkOiBBc24xRW5jb2RpbmcuUHJpbWl0aXZlLFxuICAgICAgICAgICAgdGFnOiBBc24xVGFnLk51bGwsXG4gICAgICAgIH0pLFxuICAgICAgICBlbmNvZGVMZW5ndGgoMCksXG4gICAgXSk7XG59XG4vKipcbiAqIFJTQSBlbmNyeXB0aW9uIG9iamVjdCBpZGVudGlmaWVyIGNvbnN0YW50XG4gKlxuICogRnJvbTogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzgwMTdcbiAqXG4gKiBwa2NzLTEgICAgT0JKRUNUIElERU5USUZJRVIgOjo9IHtcbiAqICAgICBpc28oMSkgbWVtYmVyLWJvZHkoMikgdXMoODQwKSByc2Fkc2koMTEzNTQ5KSBwa2NzKDEpIDFcbiAqIH1cbiAqXG4gKiAtLSBXaGVuIHJzYUVuY3J5cHRpb24gaXMgdXNlZCBpbiBhbiBBbGdvcml0aG1JZGVudGlmaWVyLFxuICogLS0gdGhlIHBhcmFtZXRlcnMgTVVTVCBiZSBwcmVzZW50IGFuZCBNVVNUIGJlIE5VTEwuXG4gKiAtLVxuICogcnNhRW5jcnlwdGlvbiAgICBPQkpFQ1QgSURFTlRJRklFUiA6Oj0geyBwa2NzLTEgMSB9XG4gKlxuICogU2VlIGFsc286IGh0dHA6Ly93d3cub2lkLWluZm8uY29tL2dldC8xLjIuODQwLjExMzU0OS4xLjEuMVxuICovXG5jb25zdCBBTEdPUklUSE1fUlNBX0VOQ1JZUFRJT04gPSBlbmNvZGVTZXF1ZW5jZShbXG4gICAgZW5jb2RlT2JqZWN0SWRlbnRpZmllcihcIjEuMi44NDAuMTEzNTQ5LjEuMS4xXCIpLFxuICAgIGVuY29kZU51bGwoKSwgLy8gcGFyYW1ldGVyc1xuXSk7XG4vKipcbiAqIFRyYW5zZm9ybSBhbiBSU0EgcHVibGljIGtleSwgd2hpY2ggaXMgYSBwYWlyIG9mIG1vZHVsdXMgKG4pIGFuZCBleHBvbmVudCAoZSksXG4gKiAgaW50byBhIGJ1ZmZlciBwZXIgQVNOLjEgc3BlYyAoREVSLWVuY29kaW5nKVxuICpcbiAqIEBwYXJhbSBuIC0gVGhlIG1vZHVsdXMgb2YgdGhlIHB1YmxpYyBrZXkgYXMgYnVmZmVyXG4gKiBAcGFyYW0gZSAtIFRoZSBleHBvbmVudCBvZiB0aGUgcHVibGljIGtleSBhcyBidWZmZXJcbiAqIEByZXR1cm5zIFRoZSBidWZmZXIsIHdoaWNoIGlzIHRoZSBwdWJsaWMga2V5IGVuY29kZWQgcGVyIEFTTi4xIHNwZWMgKERFUi1lbmNvZGluZylcbiAqL1xuZnVuY3Rpb24gY29uc3RydWN0UHVibGljS2V5SW5EZXJGb3JtYXQobiwgZSkge1xuICAgIHJldHVybiBlbmNvZGVTZXF1ZW5jZShbXG4gICAgICAgIEFMR09SSVRITV9SU0FfRU5DUllQVElPTixcbiAgICAgICAgZW5jb2RlQnVmZmVyQXNCaXRTdHJpbmcoZW5jb2RlU2VxdWVuY2UoW2VuY29kZUJ1ZmZlckFzSW50ZWdlcihuKSwgZW5jb2RlQnVmZmVyQXNJbnRlZ2VyKGUpXSkpLFxuICAgIF0pO1xufVxuZXhwb3J0cy5jb25zdHJ1Y3RQdWJsaWNLZXlJbkRlckZvcm1hdCA9IGNvbnN0cnVjdFB1YmxpY0tleUluRGVyRm9ybWF0O1xuLyoqXG4gKiBEZWNvZGUgYW4gQVNOLjEgaWRlbnRpZmllciAoYSBudW1iZXIpIGludG8gaXRzIHBhcnRzOiBjbGFzcywgcHJpbWl0aXZlT3JDb25zdHJ1Y3RlZCwgdGFnXG4gKiBTZWUgaHR0cHM6Ly93d3cuaXR1LmludC9JVFUtVC9zdHVkeWdyb3Vwcy9jb20xNy9sYW5ndWFnZXMvWC42OTAtMDIwNy5wZGYgY2hhcHRlciA4LjEuMlxuICpcbiAqIEBwYXJhbSBpZGVudGlmaWVyIC0gVGhlIGlkZW50aWZpZXJcbiAqIEByZXR1cm5zIEFuIG9iamVjdCB3aXRoIHByb3BlcnRpZXMgY2xhc3MsIHByaW1pdGl2ZU9yQ29uc3RydWN0ZWQsIHRhZ1xuICovXG5mdW5jdGlvbiBkZWNvZGVJZGVudGlmaWVyKGlkZW50aWZpZXIpIHtcbiAgICBpZiAoaWRlbnRpZmllciA+PiAzID09PSAwYjExMTExKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkFzbjFEZWNvZGluZ0Vycm9yKFwiRGVjb2Rpbmcgb2YgaWRlbnRpZmllciB3aXRoIHRhZyA+IDMwIG5vdCBpbXBsZW1lbnRlZFwiKTtcbiAgICB9XG4gICAgcmV0dXJuIHtcbiAgICAgICAgY2xhc3M6IGlkZW50aWZpZXIgPj4gNixcbiAgICAgICAgcHJpbWl0aXZlT3JDb25zdHJ1Y3RlZDogKGlkZW50aWZpZXIgPj4gNSkgJiAwYjAwMSxcbiAgICAgICAgdGFnOiBpZGVudGlmaWVyICYgMGIxMTExMSwgLy8gYml0IDEtNVxuICAgIH07XG59XG4vKipcbiAqIERlY29kZSBhbiBBU04uMSBibG9jayBvZiBsZW5ndGggdmFsdWUgY29tYmluYXRpb25zLFxuICogYW5kIHJldHVybiB0aGUgbGVuZ3RoIGFuZCBieXRlIHJhbmdlIG9mIHRoZSBmaXJzdCBsZW5ndGggdmFsdWUgY29tYmluYXRpb24uXG4gKiBTZWUgaHR0cHM6Ly93d3cuaXR1LmludC9JVFUtVC9zdHVkeWdyb3Vwcy9jb20xNy9sYW5ndWFnZXMvWC42OTAtMDIwNy5wZGYgY2hhcHRlciA4LjEuMyAtIDguMS41XG4gKlxuICogQHBhcmFtIGJsb2NrT2ZMZW5ndGhWYWx1ZXMgLSBUaGUgQVNOLjEgbGVuZ3RoIHZhbHVlXG4gKiBAcmV0dXJucyBUaGUgbGVuZ3RoIGFuZCBieXRlIHJhbmdlIG9mIHRoZSBmaXJzdCBpbmNsdWRlZCBsZW5ndGggdmFsdWVcbiAqL1xuZnVuY3Rpb24gZGVjb2RlTGVuZ3RoVmFsdWUoYmxvY2tPZkxlbmd0aFZhbHVlcykge1xuICAgIGlmICghKGJsb2NrT2ZMZW5ndGhWYWx1ZXNbMF0gJiAwYjEwMDAwMDAwKSkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgbGVuZ3RoOiBibG9ja09mTGVuZ3RoVmFsdWVzWzBdLFxuICAgICAgICAgICAgZmlyc3RCeXRlT2Zmc2V0OiAxLFxuICAgICAgICAgICAgbGFzdEJ5dGVPZmZzZXQ6IDEgKyBibG9ja09mTGVuZ3RoVmFsdWVzWzBdLFxuICAgICAgICB9O1xuICAgIH1cbiAgICBjb25zdCBuckxlbmd0aE9jdGV0cyA9IGJsb2NrT2ZMZW5ndGhWYWx1ZXNbMF0gJiAwYjAxMTExMTExO1xuICAgIGNvbnN0IGxlbmd0aCA9IEJ1ZmZlci5mcm9tKGJsb2NrT2ZMZW5ndGhWYWx1ZXMuc2xpY2UoMSwgMSArIDEgKyBuckxlbmd0aE9jdGV0cykpLnJlYWRVSW50QkUoMCwgbnJMZW5ndGhPY3RldHMpO1xuICAgIHJldHVybiB7XG4gICAgICAgIGxlbmd0aCxcbiAgICAgICAgZmlyc3RCeXRlT2Zmc2V0OiAxICsgbnJMZW5ndGhPY3RldHMsXG4gICAgICAgIGxhc3RCeXRlT2Zmc2V0OiAxICsgbnJMZW5ndGhPY3RldHMgKyBsZW5ndGgsXG4gICAgfTtcbn1cbi8qKlxuICogRGVjb2RlIGFuIEFTTi4xIHNlcXVlbmNlIGludG8gaXRzIGNvbnN0aXR1ZW50IHBhcnRzLCBlYWNoIHBhcnQgYmVpbmcgYW4gaWRlbnRpZmllci1sZW5ndGgtdmFsdWUgdHJpcGxldFxuICogU2VlIGh0dHBzOi8vd3d3Lml0dS5pbnQvSVRVLVQvc3R1ZHlncm91cHMvY29tMTcvbGFuZ3VhZ2VzL1guNjkwLTAyMDcucGRmIGNoYXB0ZXIgOC45XG4gKlxuICogQHBhcmFtIHNlcXVlbmNlVmFsdWUgLSBUaGUgQVNOLjEgc2VxdWVuY2UgdmFsdWVcbiAqIEByZXR1cm5zIEFycmF5IG9mIGlkZW50aWZpZXItbGVuZ3RoLXZhbHVlIHRyaXBsZXRzXG4gKi9cbmZ1bmN0aW9uIGRlY29kZVNlcXVlbmNlKHNlcXVlbmNlKSB7XG4gICAgY29uc3QgeyB0YWcgfSA9IGRlY29kZUlkZW50aWZpZXIoc2VxdWVuY2VbMF0pO1xuICAgIGlmICh0YWcgIT09IEFzbjFUYWcuU2VxdWVuY2UpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuQXNuMURlY29kaW5nRXJyb3IoYEV4cGVjdGVkIGEgc2VxdWVuY2UgdG8gZGVjb2RlLCBidXQgZ290IHRhZyAke3RhZ31gKTtcbiAgICB9XG4gICAgY29uc3QgeyBmaXJzdEJ5dGVPZmZzZXQsIGxhc3RCeXRlT2Zmc2V0IH0gPSBkZWNvZGVMZW5ndGhWYWx1ZShzZXF1ZW5jZS5zbGljZSgxKSk7XG4gICAgY29uc3Qgc2VxdWVuY2VWYWx1ZSA9IHNlcXVlbmNlLnNsaWNlKDEgKyBmaXJzdEJ5dGVPZmZzZXQsIDEgKyAxICsgbGFzdEJ5dGVPZmZzZXQpO1xuICAgIGNvbnN0IHBhcnRzID0gW107XG4gICAgbGV0IG9mZnNldCA9IDA7XG4gICAgd2hpbGUgKG9mZnNldCA8IHNlcXVlbmNlVmFsdWUubGVuZ3RoKSB7XG4gICAgICAgIC8vIFNpbGVuY2UgZmFsc2UgcG9zdGl2ZTogYWNjZXNzaW5nIGFuIG9jdGV0IGluIGEgQnVmZmVyIGF0IGEgcGFydGljdWxhciBpbmRleFxuICAgICAgICAvLyBpcyB0byBiZSBkb25lIHdpdGggaW5kZXggb3BlcmF0b3I6IFtpbmRleF1cbiAgICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIHNlY3VyaXR5L2RldGVjdC1vYmplY3QtaW5qZWN0aW9uXG4gICAgICAgIGNvbnN0IGlkZW50aWZpZXIgPSBkZWNvZGVJZGVudGlmaWVyKHNlcXVlbmNlVmFsdWVbb2Zmc2V0XSk7XG4gICAgICAgIGNvbnN0IG5leHQgPSBkZWNvZGVMZW5ndGhWYWx1ZShzZXF1ZW5jZVZhbHVlLnNsaWNlKG9mZnNldCArIDEpKTtcbiAgICAgICAgY29uc3QgdmFsdWUgPSBzZXF1ZW5jZVZhbHVlLnNsaWNlKG9mZnNldCArIDEgKyBuZXh0LmZpcnN0Qnl0ZU9mZnNldCwgb2Zmc2V0ICsgMSArIG5leHQubGFzdEJ5dGVPZmZzZXQpO1xuICAgICAgICBwYXJ0cy5wdXNoKHsgaWRlbnRpZmllciwgbGVuZ3RoOiBuZXh0Lmxlbmd0aCwgdmFsdWUgfSk7XG4gICAgICAgIG9mZnNldCArPSAxICsgbmV4dC5sYXN0Qnl0ZU9mZnNldDtcbiAgICB9XG4gICAgcmV0dXJuIHBhcnRzO1xufVxuLyoqXG4gKiBEZWNvZGUgYW4gQVNOLjEgc2VxdWVuY2UgdGhhdCBpcyB3cmFwcGVkIGluIGEgYml0IHN0cmluZ1xuICogKFdoaWNoIGlzIHRoZSB3YXkgUlNBIHB1YmxpYyBrZXlzIGFyZSBlbmNvZGVkIGluIEFTTi4xIERFUi1lbmNvZGluZylcbiAqIFNlZSBodHRwczovL3d3dy5pdHUuaW50L0lUVS1UL3N0dWR5Z3JvdXBzL2NvbTE3L2xhbmd1YWdlcy9YLjY5MC0wMjA3LnBkZiBjaGFwdGVyIDguNiBhbmQgOC45XG4gKlxuICogQHBhcmFtIGJpdFN0cmluZ1ZhbHVlIC0gVGhlIEFTTi4xIGJpdCBzdHJpbmcgdmFsdWVcbiAqIEByZXR1cm5zIEFycmF5IG9mIGlkZW50aWZpZXItbGVuZ3RoLXZhbHVlIHRyaXBsZXRzXG4gKi9cbmZ1bmN0aW9uIGRlY29kZUJpdFN0cmluZ1dyYXBwZWRTZXF1ZW5jZVZhbHVlKGJpdFN0cmluZ1ZhbHVlKSB7XG4gICAgY29uc3Qgd3JhcHBlZFNlcXVlbmNlID0gYml0U3RyaW5nVmFsdWUuc2xpY2UoMSk7XG4gICAgcmV0dXJuIGRlY29kZVNlcXVlbmNlKHdyYXBwZWRTZXF1ZW5jZSk7XG59XG4vKipcbiAqIERlY29kZSBhbiBBU04uMSBERVItZW5jb2RlZCBwdWJsaWMga2V5LCBpbnRvIGl0cyBtb2R1bHVzIChuKSBhbmQgZXhwb25lbnQgKGUpXG4gKlxuICogQHBhcmFtIHB1YmxpY0tleSAtIFRoZSBBU04uMSBERVItZW5jb2RlZCBwdWJsaWMga2V5XG4gKiBAcmV0dXJucyBPYmplY3Qgd2l0aCBtb2R1bHVzIChuKSBhbmQgZXhwb25lbnQgKGUpXG4gKi9cbmZ1bmN0aW9uIGRlY29uc3RydWN0UHVibGljS2V5SW5EZXJGb3JtYXQocHVibGljS2V5KSB7XG4gICAgY29uc3QgWywgcHVia2V5aW5mb10gPSBkZWNvZGVTZXF1ZW5jZShwdWJsaWNLZXkpO1xuICAgIGNvbnN0IFtuLCBlXSA9IGRlY29kZUJpdFN0cmluZ1dyYXBwZWRTZXF1ZW5jZVZhbHVlKHB1YmtleWluZm8udmFsdWUpO1xuICAgIHJldHVybiB7IG46IG4udmFsdWUsIGU6IGUudmFsdWUgfTtcbn1cbmV4cG9ydHMuZGVjb25zdHJ1Y3RQdWJsaWNLZXlJbkRlckZvcm1hdCA9IGRlY29uc3RydWN0UHVibGljS2V5SW5EZXJGb3JtYXQ7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCBBbWF6b24uY29tLCBJbmMuIG9yIGl0cyBhZmZpbGlhdGVzLiBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IEFwYWNoZS0yLjBcbi8vXG4vLyBVdGlsaXRpZXMgdG8gYXNzZXJ0IHRoYXQgc3VwcGxpZWQgdmFsdWVzIG1hdGNoIHdpdGggZXhwZWN0ZWQgdmFsdWVzXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG5leHBvcnRzLmFzc2VydElzTm90UHJvbWlzZSA9IGV4cG9ydHMuYXNzZXJ0U3RyaW5nQXJyYXlzT3ZlcmxhcCA9IGV4cG9ydHMuYXNzZXJ0U3RyaW5nQXJyYXlDb250YWluc1N0cmluZyA9IGV4cG9ydHMuYXNzZXJ0U3RyaW5nRXF1YWxzID0gdm9pZCAwO1xuY29uc3QgZXJyb3JfanNfMSA9IHJlcXVpcmUoXCIuL2Vycm9yLmpzXCIpO1xuLyoqXG4gKiBBc3NlcnQgdmFsdWUgaXMgYSBub24tZW1wdHkgc3RyaW5nIGFuZCBlcXVhbCB0byB0aGUgZXhwZWN0ZWQgdmFsdWUsXG4gKiBvciB0aHJvdyBhbiBlcnJvciBvdGhlcndpc2VcbiAqXG4gKiBAcGFyYW0gbmFtZSAtIE5hbWUgZm9yIHRoZSB2YWx1ZSBiZWluZyBjaGVja2VkXG4gKiBAcGFyYW0gYWN0dWFsIC0gVGhlIHZhbHVlIHRvIGNoZWNrXG4gKiBAcGFyYW0gZXhwZWN0ZWQgLSBUaGUgZXhwZWN0ZWQgdmFsdWVcbiAqIEBwYXJhbSBlcnJvckNvbnN0cnVjdG9yIC0gQ29uc3RydWN0b3IgZm9yIHRoZSBjb25jcmV0ZSBlcnJvciB0byBiZSB0aHJvd25cbiAqL1xuZnVuY3Rpb24gYXNzZXJ0U3RyaW5nRXF1YWxzKG5hbWUsIGFjdHVhbCwgZXhwZWN0ZWQsIGVycm9yQ29uc3RydWN0b3IgPSBlcnJvcl9qc18xLkZhaWxlZEFzc2VydGlvbkVycm9yKSB7XG4gICAgaWYgKCFhY3R1YWwpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yQ29uc3RydWN0b3IoYE1pc3NpbmcgJHtuYW1lfS4gRXhwZWN0ZWQ6ICR7ZXhwZWN0ZWR9YCwgYWN0dWFsLCBleHBlY3RlZCk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgYWN0dWFsICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvckNvbnN0cnVjdG9yKGAke25hbWV9IGlzIG5vdCBvZiB0eXBlIHN0cmluZ2AsIGFjdHVhbCwgZXhwZWN0ZWQpO1xuICAgIH1cbiAgICBpZiAoZXhwZWN0ZWQgIT09IGFjdHVhbCkge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JDb25zdHJ1Y3RvcihgJHtuYW1lfSBub3QgYWxsb3dlZDogJHthY3R1YWx9LiBFeHBlY3RlZDogJHtleHBlY3RlZH1gLCBhY3R1YWwsIGV4cGVjdGVkKTtcbiAgICB9XG59XG5leHBvcnRzLmFzc2VydFN0cmluZ0VxdWFscyA9IGFzc2VydFN0cmluZ0VxdWFscztcbi8qKlxuICogQXNzZXJ0IHZhbHVlIGlzIGEgbm9uLWVtcHR5IHN0cmluZyBhbmQgaXMgaW5kZWVkIG9uZSBvZiB0aGUgZXhwZWN0ZWQgdmFsdWVzLFxuICogb3IgdGhyb3cgYW4gZXJyb3Igb3RoZXJ3aXNlXG4gKlxuICogQHBhcmFtIG5hbWUgLSBOYW1lIGZvciB0aGUgdmFsdWUgYmVpbmcgY2hlY2tlZFxuICogQHBhcmFtIGFjdHVhbCAtIFRoZSB2YWx1ZSB0byBjaGVja1xuICogQHBhcmFtIGV4cGVjdGVkIC0gVGhlIGFycmF5IG9mIGV4cGVjdGVkIHZhbHVlcy4gRm9yIHlvdXIgY29udmVuaWVuY2UgeW91IGNhbiBwcm92aWRlXG4gKiBAcGFyYW0gZXJyb3JDb25zdHJ1Y3RvciAtIENvbnN0cnVjdG9yIGZvciB0aGUgY29uY3JldGUgZXJyb3IgdG8gYmUgdGhyb3duXG4gKiBhIHN0cmluZyBoZXJlIGFzIHdlbGwsIHdoaWNoIHdpbGwgbWVhbiBhbiBhcnJheSB3aXRoIGp1c3QgdGhhdCBzdHJpbmdcbiAqL1xuZnVuY3Rpb24gYXNzZXJ0U3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhuYW1lLCBhY3R1YWwsIGV4cGVjdGVkLCBlcnJvckNvbnN0cnVjdG9yID0gZXJyb3JfanNfMS5GYWlsZWRBc3NlcnRpb25FcnJvcikge1xuICAgIGlmICghYWN0dWFsKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvckNvbnN0cnVjdG9yKGBNaXNzaW5nICR7bmFtZX0uICR7ZXhwZWN0YXRpb25NZXNzYWdlKGV4cGVjdGVkKX1gLCBhY3R1YWwsIGV4cGVjdGVkKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBhY3R1YWwgIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yQ29uc3RydWN0b3IoYCR7bmFtZX0gaXMgbm90IG9mIHR5cGUgc3RyaW5nYCwgYWN0dWFsLCBleHBlY3RlZCk7XG4gICAgfVxuICAgIHJldHVybiBhc3NlcnRTdHJpbmdBcnJheXNPdmVybGFwKG5hbWUsIGFjdHVhbCwgZXhwZWN0ZWQsIGVycm9yQ29uc3RydWN0b3IpO1xufVxuZXhwb3J0cy5hc3NlcnRTdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nID0gYXNzZXJ0U3RyaW5nQXJyYXlDb250YWluc1N0cmluZztcbi8qKlxuICogQXNzZXJ0IHZhbHVlIGlzIGFuIGFycmF5IG9mIHN0cmluZ3MsIHdoZXJlIGF0IGxlYXN0IG9uZSBvZiB0aGUgc3RyaW5ncyBpcyBpbmRlZWQgb25lIG9mIHRoZSBleHBlY3RlZCB2YWx1ZXMsXG4gKiBvciB0aHJvdyBhbiBlcnJvciBvdGhlcndpc2VcbiAqXG4gKiBAcGFyYW0gbmFtZSAtIE5hbWUgZm9yIHRoZSB2YWx1ZSBiZWluZyBjaGVja2VkXG4gKiBAcGFyYW0gYWN0dWFsIC0gVGhlIHZhbHVlIHRvIGNoZWNrLCBtdXN0IGJlIGFuIGFycmF5IG9mIHN0cmluZ3MsIG9yIGEgc2luZ2xlIHN0cmluZyAod2hpY2ggd2lsbCBiZSB0cmVhdGVkXG4gKiBhcyBhbiBhcnJheSB3aXRoIGp1c3QgdGhhdCBzdHJpbmcpXG4gKiBAcGFyYW0gZXhwZWN0ZWQgLSBUaGUgYXJyYXkgb2YgZXhwZWN0ZWQgdmFsdWVzLiBGb3IgeW91ciBjb252ZW5pZW5jZSB5b3UgY2FuIHByb3ZpZGVcbiAqIGEgc3RyaW5nIGhlcmUgYXMgd2VsbCwgd2hpY2ggd2lsbCBtZWFuIGFuIGFycmF5IHdpdGgganVzdCB0aGF0IHN0cmluZ1xuICogQHBhcmFtIGVycm9yQ29uc3RydWN0b3IgLSBDb25zdHJ1Y3RvciBmb3IgdGhlIGNvbmNyZXRlIGVycm9yIHRvIGJlIHRocm93blxuICovXG5mdW5jdGlvbiBhc3NlcnRTdHJpbmdBcnJheXNPdmVybGFwKG5hbWUsIGFjdHVhbCwgZXhwZWN0ZWQsIGVycm9yQ29uc3RydWN0b3IgPSBlcnJvcl9qc18xLkZhaWxlZEFzc2VydGlvbkVycm9yKSB7XG4gICAgaWYgKCFhY3R1YWwpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yQ29uc3RydWN0b3IoYE1pc3NpbmcgJHtuYW1lfS4gJHtleHBlY3RhdGlvbk1lc3NhZ2UoZXhwZWN0ZWQpfWAsIGFjdHVhbCwgZXhwZWN0ZWQpO1xuICAgIH1cbiAgICBjb25zdCBleHBlY3RlZEFzU2V0ID0gbmV3IFNldChBcnJheS5pc0FycmF5KGV4cGVjdGVkKSA/IGV4cGVjdGVkIDogW2V4cGVjdGVkXSk7XG4gICAgaWYgKHR5cGVvZiBhY3R1YWwgPT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgYWN0dWFsID0gW2FjdHVhbF07XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShhY3R1YWwpKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvckNvbnN0cnVjdG9yKGAke25hbWV9IGlzIG5vdCBhbiBhcnJheWAsIGFjdHVhbCwgZXhwZWN0ZWQpO1xuICAgIH1cbiAgICBjb25zdCBvdmVybGFwcyA9IGFjdHVhbC5zb21lKChhY3R1YWxJdGVtKSA9PiB7XG4gICAgICAgIGlmICh0eXBlb2YgYWN0dWFsSXRlbSAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yQ29uc3RydWN0b3IoYCR7bmFtZX0gaW5jbHVkZXMgZWxlbWVudHMgdGhhdCBhcmUgbm90IG9mIHR5cGUgc3RyaW5nYCwgYWN0dWFsLCBleHBlY3RlZCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGV4cGVjdGVkQXNTZXQuaGFzKGFjdHVhbEl0ZW0pO1xuICAgIH0pO1xuICAgIGlmICghb3ZlcmxhcHMpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yQ29uc3RydWN0b3IoYCR7bmFtZX0gbm90IGFsbG93ZWQ6ICR7YWN0dWFsLmpvaW4oXCIsIFwiKX0uICR7ZXhwZWN0YXRpb25NZXNzYWdlKGV4cGVjdGVkKX1gLCBhY3R1YWwsIGV4cGVjdGVkKTtcbiAgICB9XG59XG5leHBvcnRzLmFzc2VydFN0cmluZ0FycmF5c092ZXJsYXAgPSBhc3NlcnRTdHJpbmdBcnJheXNPdmVybGFwO1xuLyoqXG4gKiBHZXQgYSBuaWNlbHkgcmVhZGFibGUgbWVzc2FnZSByZWdhcmRpbmcgYW4gZXhwZWN0YXRpb25cbiAqXG4gKiBAcGFyYW0gZXhwZWN0ZWQgLSBUaGUgZXhwZWN0ZWQgdmFsdWUuXG4gKi9cbmZ1bmN0aW9uIGV4cGVjdGF0aW9uTWVzc2FnZShleHBlY3RlZCkge1xuICAgIGlmIChBcnJheS5pc0FycmF5KGV4cGVjdGVkKSkge1xuICAgICAgICBpZiAoZXhwZWN0ZWQubGVuZ3RoID4gMSkge1xuICAgICAgICAgICAgcmV0dXJuIGBFeHBlY3RlZCBvbmUgb2Y6ICR7ZXhwZWN0ZWQuam9pbihcIiwgXCIpfWA7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGBFeHBlY3RlZDogJHtleHBlY3RlZFswXX1gO1xuICAgIH1cbiAgICByZXR1cm4gYEV4cGVjdGVkOiAke2V4cGVjdGVkfWA7XG59XG4vKipcbiAqIEFzc2VydCB2YWx1ZSBpcyBub3QgYSBwcm9taXNlLCBvciB0aHJvdyBhbiBlcnJvciBvdGhlcndpc2VcbiAqXG4gKiBAcGFyYW0gYWN0dWFsIC0gVGhlIHZhbHVlIHRvIGNoZWNrXG4gKiBAcGFyYW0gZXJyb3JGYWN0b3J5IC0gRnVuY3Rpb24gdGhhdCByZXR1cm5zIHRoZSBlcnJvciB0byBiZSB0aHJvd25cbiAqL1xuZnVuY3Rpb24gYXNzZXJ0SXNOb3RQcm9taXNlKGFjdHVhbCwgZXJyb3JGYWN0b3J5KSB7XG4gICAgaWYgKGFjdHVhbCAmJiB0eXBlb2YgYWN0dWFsLnRoZW4gPT09IFwiZnVuY3Rpb25cIikge1xuICAgICAgICB0aHJvdyBlcnJvckZhY3RvcnkoKTtcbiAgICB9XG59XG5leHBvcnRzLmFzc2VydElzTm90UHJvbWlzZSA9IGFzc2VydElzTm90UHJvbWlzZTtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IEFtYXpvbi5jb20sIEluYy4gb3IgaXRzIGFmZmlsaWF0ZXMuIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4vLyBTUERYLUxpY2Vuc2UtSWRlbnRpZmllcjogQXBhY2hlLTIuMFxuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xuZXhwb3J0cy5Db2duaXRvSnd0VmVyaWZpZXIgPSB2b2lkIDA7XG5jb25zdCBlcnJvcl9qc18xID0gcmVxdWlyZShcIi4vZXJyb3IuanNcIik7XG5jb25zdCBqd3RfcnNhX2pzXzEgPSByZXF1aXJlKFwiLi9qd3QtcnNhLmpzXCIpO1xuY29uc3QgYXNzZXJ0X2pzXzEgPSByZXF1aXJlKFwiLi9hc3NlcnQuanNcIik7XG4vKipcbiAqIFZhbGlkYXRlIGNsYWltcyBvZiBhIGRlY29kZWQgQ29nbml0byBKV1QuXG4gKiBUaGlzIGZ1bmN0aW9uIHRocm93cyBhbiBlcnJvciBpbiBjYXNlIHRoZXJlJ3MgYW55IHZhbGlkYXRpb24gaXNzdWUuXG4gKlxuICogQHBhcmFtIHBheWxvYWQgLSBUaGUgSlNPTiBwYXJzZWQgcGF5bG9hZCBvZiB0aGUgQ29nbml0byBKV1RcbiAqIEBwYXJhbSBvcHRpb25zIC0gVmFsaWRhdGlvbiBvcHRpb25zXG4gKiBAcGFyYW0gb3B0aW9ucy5ncm91cHMgLSBUaGUgY29nbml0byBncm91cHMsIG9mIHdoaWNoIGF0IGxlYXN0IG9uZSBtdXN0IGJlIHByZXNlbnQgaW4gdGhlIEpXVCdzIGNvZ25pdG86Z3JvdXBzIGNsYWltXG4gKiBAcGFyYW0gb3B0aW9ucy50b2tlblVzZSAtIFRoZSByZXF1aXJlZCB0b2tlbiB1c2Ugb2YgdGhlIEpXVDogXCJpZFwiIG9yIFwiYWNjZXNzXCJcbiAqIEBwYXJhbSBvcHRpb25zLmNsaWVudElkIC0gVGhlIHJlcXVpcmVkIGNsaWVudElkIG9mIHRoZSBKV1QuIE1heSBiZSBhbiBhcnJheSBvZiBzdHJpbmcsIG9mIHdoaWNoIGF0IGxlYXN0IG9uZSBtdXN0IG1hdGNoXG4gKiBAcmV0dXJucyB2b2lkXG4gKi9cbmZ1bmN0aW9uIHZhbGlkYXRlQ29nbml0b0p3dEZpZWxkcyhwYXlsb2FkLCBvcHRpb25zKSB7XG4gICAgLy8gQ2hlY2sgZ3JvdXBzXG4gICAgaWYgKG9wdGlvbnMuZ3JvdXBzICE9IG51bGwpIHtcbiAgICAgICAgKDAsIGFzc2VydF9qc18xLmFzc2VydFN0cmluZ0FycmF5c092ZXJsYXApKFwiQ29nbml0byBncm91cFwiLCBwYXlsb2FkW1wiY29nbml0bzpncm91cHNcIl0sIG9wdGlvbnMuZ3JvdXBzLCBlcnJvcl9qc18xLkNvZ25pdG9Kd3RJbnZhbGlkR3JvdXBFcnJvcik7XG4gICAgfVxuICAgIC8vIENoZWNrIHRva2VuIHVzZVxuICAgICgwLCBhc3NlcnRfanNfMS5hc3NlcnRTdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKShcIlRva2VuIHVzZVwiLCBwYXlsb2FkLnRva2VuX3VzZSwgW1wiaWRcIiwgXCJhY2Nlc3NcIl0sIGVycm9yX2pzXzEuQ29nbml0b0p3dEludmFsaWRUb2tlblVzZUVycm9yKTtcbiAgICBpZiAob3B0aW9ucy50b2tlblVzZSAhPT0gbnVsbCkge1xuICAgICAgICBpZiAob3B0aW9ucy50b2tlblVzZSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5QYXJhbWV0ZXJWYWxpZGF0aW9uRXJyb3IoXCJ0b2tlblVzZSBtdXN0IGJlIHByb3ZpZGVkIG9yIHNldCB0byBudWxsIGV4cGxpY2l0bHlcIik7XG4gICAgICAgIH1cbiAgICAgICAgKDAsIGFzc2VydF9qc18xLmFzc2VydFN0cmluZ0VxdWFscykoXCJUb2tlbiB1c2VcIiwgcGF5bG9hZC50b2tlbl91c2UsIG9wdGlvbnMudG9rZW5Vc2UsIGVycm9yX2pzXzEuQ29nbml0b0p3dEludmFsaWRUb2tlblVzZUVycm9yKTtcbiAgICB9XG4gICAgLy8gQ2hlY2sgY2xpZW50SWQgYWthIGF1ZGllbmNlXG4gICAgaWYgKG9wdGlvbnMuY2xpZW50SWQgIT09IG51bGwpIHtcbiAgICAgICAgaWYgKG9wdGlvbnMuY2xpZW50SWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yKFwiY2xpZW50SWQgbXVzdCBiZSBwcm92aWRlZCBvciBzZXQgdG8gbnVsbCBleHBsaWNpdGx5XCIpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChwYXlsb2FkLnRva2VuX3VzZSA9PT0gXCJpZFwiKSB7XG4gICAgICAgICAgICAoMCwgYXNzZXJ0X2pzXzEuYXNzZXJ0U3RyaW5nQXJyYXlDb250YWluc1N0cmluZykoJ0NsaWVudCBJRCAoXCJhdWRpZW5jZVwiKScsIHBheWxvYWQuYXVkLCBvcHRpb25zLmNsaWVudElkLCBlcnJvcl9qc18xLkNvZ25pdG9Kd3RJbnZhbGlkQ2xpZW50SWRFcnJvcik7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAoMCwgYXNzZXJ0X2pzXzEuYXNzZXJ0U3RyaW5nQXJyYXlDb250YWluc1N0cmluZykoXCJDbGllbnQgSURcIiwgcGF5bG9hZC5jbGllbnRfaWQsIG9wdGlvbnMuY2xpZW50SWQsIGVycm9yX2pzXzEuQ29nbml0b0p3dEludmFsaWRDbGllbnRJZEVycm9yKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbi8qKlxuICogQ2xhc3MgcmVwcmVzZW50aW5nIGEgdmVyaWZpZXIgZm9yIEpXVHMgc2lnbmVkIGJ5IEFtYXpvbiBDb2duaXRvXG4gKi9cbmNsYXNzIENvZ25pdG9Kd3RWZXJpZmllciBleHRlbmRzIGp3dF9yc2FfanNfMS5Kd3RSc2FWZXJpZmllckJhc2Uge1xuICAgIGNvbnN0cnVjdG9yKHByb3BzLCBqd2tzQ2FjaGUpIHtcbiAgICAgICAgY29uc3QgaXNzdWVyQ29uZmlnID0gQXJyYXkuaXNBcnJheShwcm9wcylcbiAgICAgICAgICAgID8gcHJvcHMubWFwKChwKSA9PiAoe1xuICAgICAgICAgICAgICAgIC4uLnAsXG4gICAgICAgICAgICAgICAgLi4uQ29nbml0b0p3dFZlcmlmaWVyLnBhcnNlVXNlclBvb2xJZChwLnVzZXJQb29sSWQpLFxuICAgICAgICAgICAgICAgIGF1ZGllbmNlOiBudWxsLCAvLyBjaGVja2VkIGluc3RlYWQgYnkgdmFsaWRhdGVDb2duaXRvSnd0RmllbGRzXG4gICAgICAgICAgICB9KSlcbiAgICAgICAgICAgIDoge1xuICAgICAgICAgICAgICAgIC4uLnByb3BzLFxuICAgICAgICAgICAgICAgIC4uLkNvZ25pdG9Kd3RWZXJpZmllci5wYXJzZVVzZXJQb29sSWQocHJvcHMudXNlclBvb2xJZCksXG4gICAgICAgICAgICAgICAgYXVkaWVuY2U6IG51bGwsIC8vIGNoZWNrZWQgaW5zdGVhZCBieSB2YWxpZGF0ZUNvZ25pdG9Kd3RGaWVsZHNcbiAgICAgICAgICAgIH07XG4gICAgICAgIHN1cGVyKGlzc3VlckNvbmZpZywgandrc0NhY2hlKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogUGFyc2UgYSBVc2VyIFBvb2wgSUQsIHRvIGV4dHJhY3QgdGhlIGlzc3VlciBhbmQgSldLUyBVUklcbiAgICAgKlxuICAgICAqIEBwYXJhbSB1c2VyUG9vbElkIFRoZSBVc2VyIFBvb2wgSURcbiAgICAgKiBAcmV0dXJucyBUaGUgaXNzdWVyIGFuZCBKV0tTIFVSSSBmb3IgdGhlIFVzZXIgUG9vbFxuICAgICAqL1xuICAgIHN0YXRpYyBwYXJzZVVzZXJQb29sSWQodXNlclBvb2xJZCkge1xuICAgICAgICAvLyBEaXNhYmxlIHNhZmUgcmVnZXhwIGNoZWNrIGFzIHVzZXJQb29sSWQgaXMgcHJvdmlkZWQgYnkgZGV2ZWxvcGVyLCBpLmUuIGlzIG5vdCB1c2VyIGlucHV0XG4gICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBzZWN1cml0eS9kZXRlY3QtdW5zYWZlLXJlZ2V4XG4gICAgICAgIGNvbnN0IG1hdGNoID0gdXNlclBvb2xJZC5tYXRjaCgvXig/PHJlZ2lvbj4oXFx3Ky0pP1xcdystXFx3Ky1cXGQpK19cXHcrJC8pO1xuICAgICAgICBpZiAoIW1hdGNoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5QYXJhbWV0ZXJWYWxpZGF0aW9uRXJyb3IoYEludmFsaWQgQ29nbml0byBVc2VyIFBvb2wgSUQ6ICR7dXNlclBvb2xJZH1gKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCByZWdpb24gPSBtYXRjaC5ncm91cHMucmVnaW9uO1xuICAgICAgICBjb25zdCBpc3N1ZXIgPSBgaHR0cHM6Ly9jb2duaXRvLWlkcC4ke3JlZ2lvbn0uYW1hem9uYXdzLmNvbS8ke3VzZXJQb29sSWR9YDtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIGlzc3VlcixcbiAgICAgICAgICAgIGp3a3NVcmk6IGAke2lzc3Vlcn0vLndlbGwta25vd24vandrcy5qc29uYCxcbiAgICAgICAgfTtcbiAgICB9XG4gICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEB0eXBlc2NyaXB0LWVzbGludC9leHBsaWNpdC1tb2R1bGUtYm91bmRhcnktdHlwZXNcbiAgICBzdGF0aWMgY3JlYXRlKHZlcmlmeVByb3BlcnRpZXMsIGFkZGl0aW9uYWxQcm9wZXJ0aWVzKSB7XG4gICAgICAgIHJldHVybiBuZXcgdGhpcyh2ZXJpZnlQcm9wZXJ0aWVzLCBhZGRpdGlvbmFsUHJvcGVydGllcz8uandrc0NhY2hlKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogVmVyaWZ5IChzeW5jaHJvbm91c2x5KSBhIEpXVCB0aGF0IGlzIHNpZ25lZCBieSBBbWF6b24gQ29nbml0by5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBqd3QgVGhlIEpXVCwgYXMgc3RyaW5nXG4gICAgICogQHBhcmFtIHByb3BzIFZlcmlmaWNhdGlvbiBwcm9wZXJ0aWVzXG4gICAgICogQHJldHVybnMgVGhlIHBheWxvYWQgb2YgdGhlIEpXVOKAk+KAk2lmIHRoZSBKV1QgaXMgdmFsaWQsIG90aGVyd2lzZSBhbiBlcnJvciBpcyB0aHJvd25cbiAgICAgKi9cbiAgICB2ZXJpZnlTeW5jKC4uLltqd3QsIHByb3BlcnRpZXNdKSB7XG4gICAgICAgIGNvbnN0IHsgZGVjb21wb3NlZEp3dCwgandrc1VyaSwgdmVyaWZ5UHJvcGVydGllcyB9ID0gdGhpcy5nZXRWZXJpZnlQYXJhbWV0ZXJzKGp3dCwgcHJvcGVydGllcyk7XG4gICAgICAgIHRoaXMudmVyaWZ5RGVjb21wb3NlZEp3dFN5bmMoZGVjb21wb3NlZEp3dCwgandrc1VyaSwgdmVyaWZ5UHJvcGVydGllcyk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB2YWxpZGF0ZUNvZ25pdG9Kd3RGaWVsZHMoZGVjb21wb3NlZEp3dC5wYXlsb2FkLCB2ZXJpZnlQcm9wZXJ0aWVzKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICBpZiAodmVyaWZ5UHJvcGVydGllcy5pbmNsdWRlUmF3Snd0SW5FcnJvcnMgJiZcbiAgICAgICAgICAgICAgICBlcnIgaW5zdGFuY2VvZiBlcnJvcl9qc18xLkp3dEludmFsaWRDbGFpbUVycm9yKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgZXJyLndpdGhSYXdKd3QoZGVjb21wb3NlZEp3dCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGRlY29tcG9zZWRKd3QucGF5bG9hZDtcbiAgICB9XG4gICAgLyoqXG4gICAgICogVmVyaWZ5IChhc3luY2hyb25vdXNseSkgYSBKV1QgdGhhdCBpcyBzaWduZWQgYnkgQW1hem9uIENvZ25pdG8uXG4gICAgICogVGhpcyBjYWxsIGlzIGFzeW5jaHJvbm91cywgYW5kIHRoZSBKV0tTIHdpbGwgYmUgZmV0Y2hlZCBmcm9tIHRoZSBKV0tTIHVyaSxcbiAgICAgKiBpbiBjYXNlIGl0IGlzIG5vdCB5ZXQgYXZhaWxhYmxlIGluIHRoZSBjYWNoZS5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBqd3QgVGhlIEpXVCwgYXMgc3RyaW5nXG4gICAgICogQHBhcmFtIHByb3BzIFZlcmlmaWNhdGlvbiBwcm9wZXJ0aWVzXG4gICAgICogQHJldHVybnMgUHJvbWlzZSB0aGF0IHJlc29sdmVzIHRvIHRoZSBwYXlsb2FkIG9mIHRoZSBKV1TigJPigJNpZiB0aGUgSldUIGlzIHZhbGlkLCBvdGhlcndpc2UgdGhlIHByb21pc2UgcmVqZWN0c1xuICAgICAqL1xuICAgIGFzeW5jIHZlcmlmeSguLi5band0LCBwcm9wZXJ0aWVzXSkge1xuICAgICAgICBjb25zdCB7IGRlY29tcG9zZWRKd3QsIGp3a3NVcmksIHZlcmlmeVByb3BlcnRpZXMgfSA9IHRoaXMuZ2V0VmVyaWZ5UGFyYW1ldGVycyhqd3QsIHByb3BlcnRpZXMpO1xuICAgICAgICBhd2FpdCB0aGlzLnZlcmlmeURlY29tcG9zZWRKd3QoZGVjb21wb3NlZEp3dCwgandrc1VyaSwgdmVyaWZ5UHJvcGVydGllcyk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB2YWxpZGF0ZUNvZ25pdG9Kd3RGaWVsZHMoZGVjb21wb3NlZEp3dC5wYXlsb2FkLCB2ZXJpZnlQcm9wZXJ0aWVzKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICBpZiAodmVyaWZ5UHJvcGVydGllcy5pbmNsdWRlUmF3Snd0SW5FcnJvcnMgJiZcbiAgICAgICAgICAgICAgICBlcnIgaW5zdGFuY2VvZiBlcnJvcl9qc18xLkp3dEludmFsaWRDbGFpbUVycm9yKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgZXJyLndpdGhSYXdKd3QoZGVjb21wb3NlZEp3dCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGRlY29tcG9zZWRKd3QucGF5bG9hZDtcbiAgICB9XG4gICAgLyoqXG4gICAgICogVGhpcyBtZXRob2QgbG9hZHMgYSBKV0tTIHRoYXQgeW91IHByb3ZpZGUsIGludG8gdGhlIEpXS1MgY2FjaGUsIHNvIHRoYXQgaXQgaXNcbiAgICAgKiBhdmFpbGFibGUgZm9yIEpXVCB2ZXJpZmljYXRpb24uIFVzZSB0aGlzIG1ldGhvZCB0byBzcGVlZCB1cCB0aGUgZmlyc3QgSldUIHZlcmlmaWNhdGlvblxuICAgICAqICh3aGVuIHRoZSBKV0tTIHdvdWxkIG90aGVyd2lzZSBoYXZlIHRvIGJlIGRvd25sb2FkZWQgZnJvbSB0aGUgSldLUyB1cmkpLCBvciB0byBwcm92aWRlIHRoZSBKV0tTXG4gICAgICogaW4gY2FzZSB0aGUgSnd0VmVyaWZpZXIgZG9lcyBub3QgaGF2ZSBpbnRlcm5ldCBhY2Nlc3MgdG8gZG93bmxvYWQgdGhlIEpXS1NcbiAgICAgKlxuICAgICAqIEBwYXJhbSBqd2tzIFRoZSBKV0tTXG4gICAgICogQHBhcmFtIHVzZXJQb29sSWQgVGhlIHVzZXJQb29sSWQgZm9yIHdoaWNoIHlvdSB3YW50IHRvIGNhY2hlIHRoZSBKV0tTXG4gICAgICogIFN1cHBseSB0aGlzIGZpZWxkLCBpZiB5b3UgaW5zdGFudGlhdGVkIHRoZSBDb2duaXRvSnd0VmVyaWZpZXIgd2l0aCBtdWx0aXBsZSB1c2VyUG9vbElkc1xuICAgICAqIEByZXR1cm5zIHZvaWRcbiAgICAgKi9cbiAgICBjYWNoZUp3a3MoLi4uW2p3a3MsIHVzZXJQb29sSWRdKSB7XG4gICAgICAgIGxldCBpc3N1ZXI7XG4gICAgICAgIGlmICh1c2VyUG9vbElkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIGlzc3VlciA9IENvZ25pdG9Kd3RWZXJpZmllci5wYXJzZVVzZXJQb29sSWQodXNlclBvb2xJZCkuaXNzdWVyO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuZXhwZWN0ZWRJc3N1ZXJzLmxlbmd0aCA+IDEpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLlBhcmFtZXRlclZhbGlkYXRpb25FcnJvcihcInVzZXJQb29sSWQgbXVzdCBiZSBwcm92aWRlZFwiKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBpc3N1ZXJDb25maWcgPSB0aGlzLmdldElzc3VlckNvbmZpZyhpc3N1ZXIpO1xuICAgICAgICBzdXBlci5jYWNoZUp3a3MoandrcywgaXNzdWVyQ29uZmlnLmlzc3Vlcik7XG4gICAgfVxufVxuZXhwb3J0cy5Db2duaXRvSnd0VmVyaWZpZXIgPSBDb2duaXRvSnd0VmVyaWZpZXI7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCBBbWF6b24uY29tLCBJbmMuIG9yIGl0cyBhZmZpbGlhdGVzLiBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IEFwYWNoZS0yLjBcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbmV4cG9ydHMuTm9uUmV0cnlhYmxlRmV0Y2hFcnJvciA9IGV4cG9ydHMuRmV0Y2hFcnJvciA9IGV4cG9ydHMuSndrSW52YWxpZEt0eUVycm9yID0gZXhwb3J0cy5Kd2tJbnZhbGlkVXNlRXJyb3IgPSBleHBvcnRzLkp3a3NOb3RBdmFpbGFibGVJbkNhY2hlRXJyb3IgPSBleHBvcnRzLldhaXRQZXJpb2ROb3RZZXRFbmRlZEp3a0Vycm9yID0gZXhwb3J0cy5LaWROb3RGb3VuZEluSndrc0Vycm9yID0gZXhwb3J0cy5Kd3RXaXRob3V0VmFsaWRLaWRFcnJvciA9IGV4cG9ydHMuSndrVmFsaWRhdGlvbkVycm9yID0gZXhwb3J0cy5Kd2tzVmFsaWRhdGlvbkVycm9yID0gZXhwb3J0cy5Bc24xRGVjb2RpbmdFcnJvciA9IGV4cG9ydHMuQ29nbml0b0p3dEludmFsaWRDbGllbnRJZEVycm9yID0gZXhwb3J0cy5Db2duaXRvSnd0SW52YWxpZFRva2VuVXNlRXJyb3IgPSBleHBvcnRzLkNvZ25pdG9Kd3RJbnZhbGlkR3JvdXBFcnJvciA9IGV4cG9ydHMuSnd0Tm90QmVmb3JlRXJyb3IgPSBleHBvcnRzLkp3dEV4cGlyZWRFcnJvciA9IGV4cG9ydHMuSnd0SW52YWxpZFNjb3BlRXJyb3IgPSBleHBvcnRzLkp3dEludmFsaWRBdWRpZW5jZUVycm9yID0gZXhwb3J0cy5Kd3RJbnZhbGlkSXNzdWVyRXJyb3IgPSBleHBvcnRzLkp3dEludmFsaWRDbGFpbUVycm9yID0gZXhwb3J0cy5Kd3RJbnZhbGlkU2lnbmF0dXJlQWxnb3JpdGhtRXJyb3IgPSBleHBvcnRzLkp3dEludmFsaWRTaWduYXR1cmVFcnJvciA9IGV4cG9ydHMuUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yID0gZXhwb3J0cy5Kd3RQYXJzZUVycm9yID0gZXhwb3J0cy5GYWlsZWRBc3NlcnRpb25FcnJvciA9IGV4cG9ydHMuSnd0QmFzZUVycm9yID0gdm9pZCAwO1xuLyoqXG4gKiBCYXNlIEVycm9yIGZvciBhbGwgb3RoZXIgZXJyb3JzIGluIHRoaXMgZmlsZVxuICovXG5jbGFzcyBKd3RCYXNlRXJyb3IgZXh0ZW5kcyBFcnJvciB7XG59XG5leHBvcnRzLkp3dEJhc2VFcnJvciA9IEp3dEJhc2VFcnJvcjtcbi8qKlxuICogQW4gZXJyb3IgdGhhdCBpcyByYWlzZWQgYmVjYXVzZSBhbiBhY3R1YWwgdmFsdWUgZG9lcyBub3QgbWF0Y2ggd2l0aCB0aGUgZXhwZWN0ZWQgdmFsdWVcbiAqL1xuY2xhc3MgRmFpbGVkQXNzZXJ0aW9uRXJyb3IgZXh0ZW5kcyBKd3RCYXNlRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKG1zZywgYWN0dWFsLCBleHBlY3RlZCkge1xuICAgICAgICBzdXBlcihtc2cpO1xuICAgICAgICB0aGlzLmZhaWxlZEFzc2VydGlvbiA9IHtcbiAgICAgICAgICAgIGFjdHVhbCxcbiAgICAgICAgICAgIGV4cGVjdGVkLFxuICAgICAgICB9O1xuICAgIH1cbn1cbmV4cG9ydHMuRmFpbGVkQXNzZXJ0aW9uRXJyb3IgPSBGYWlsZWRBc3NlcnRpb25FcnJvcjtcbi8qKlxuICogSldUIGVycm9yc1xuICovXG5jbGFzcyBKd3RQYXJzZUVycm9yIGV4dGVuZHMgSnd0QmFzZUVycm9yIHtcbiAgICBjb25zdHJ1Y3Rvcihtc2csIGVycm9yKSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2UgPSBlcnJvciAhPSBudWxsID8gYCR7bXNnfTogJHtlcnJvcn1gIDogbXNnO1xuICAgICAgICBzdXBlcihtZXNzYWdlKTtcbiAgICB9XG59XG5leHBvcnRzLkp3dFBhcnNlRXJyb3IgPSBKd3RQYXJzZUVycm9yO1xuY2xhc3MgUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yIGV4dGVuZHMgSnd0QmFzZUVycm9yIHtcbn1cbmV4cG9ydHMuUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yID0gUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yO1xuY2xhc3MgSnd0SW52YWxpZFNpZ25hdHVyZUVycm9yIGV4dGVuZHMgSnd0QmFzZUVycm9yIHtcbn1cbmV4cG9ydHMuSnd0SW52YWxpZFNpZ25hdHVyZUVycm9yID0gSnd0SW52YWxpZFNpZ25hdHVyZUVycm9yO1xuY2xhc3MgSnd0SW52YWxpZFNpZ25hdHVyZUFsZ29yaXRobUVycm9yIGV4dGVuZHMgRmFpbGVkQXNzZXJ0aW9uRXJyb3Ige1xufVxuZXhwb3J0cy5Kd3RJbnZhbGlkU2lnbmF0dXJlQWxnb3JpdGhtRXJyb3IgPSBKd3RJbnZhbGlkU2lnbmF0dXJlQWxnb3JpdGhtRXJyb3I7XG5jbGFzcyBKd3RJbnZhbGlkQ2xhaW1FcnJvciBleHRlbmRzIEZhaWxlZEFzc2VydGlvbkVycm9yIHtcbiAgICB3aXRoUmF3Snd0KHsgaGVhZGVyLCBwYXlsb2FkIH0pIHtcbiAgICAgICAgdGhpcy5yYXdKd3QgPSB7XG4gICAgICAgICAgICBoZWFkZXIsXG4gICAgICAgICAgICBwYXlsb2FkLFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG59XG5leHBvcnRzLkp3dEludmFsaWRDbGFpbUVycm9yID0gSnd0SW52YWxpZENsYWltRXJyb3I7XG5jbGFzcyBKd3RJbnZhbGlkSXNzdWVyRXJyb3IgZXh0ZW5kcyBKd3RJbnZhbGlkQ2xhaW1FcnJvciB7XG59XG5leHBvcnRzLkp3dEludmFsaWRJc3N1ZXJFcnJvciA9IEp3dEludmFsaWRJc3N1ZXJFcnJvcjtcbmNsYXNzIEp3dEludmFsaWRBdWRpZW5jZUVycm9yIGV4dGVuZHMgSnd0SW52YWxpZENsYWltRXJyb3Ige1xufVxuZXhwb3J0cy5Kd3RJbnZhbGlkQXVkaWVuY2VFcnJvciA9IEp3dEludmFsaWRBdWRpZW5jZUVycm9yO1xuY2xhc3MgSnd0SW52YWxpZFNjb3BlRXJyb3IgZXh0ZW5kcyBKd3RJbnZhbGlkQ2xhaW1FcnJvciB7XG59XG5leHBvcnRzLkp3dEludmFsaWRTY29wZUVycm9yID0gSnd0SW52YWxpZFNjb3BlRXJyb3I7XG5jbGFzcyBKd3RFeHBpcmVkRXJyb3IgZXh0ZW5kcyBKd3RJbnZhbGlkQ2xhaW1FcnJvciB7XG59XG5leHBvcnRzLkp3dEV4cGlyZWRFcnJvciA9IEp3dEV4cGlyZWRFcnJvcjtcbmNsYXNzIEp3dE5vdEJlZm9yZUVycm9yIGV4dGVuZHMgSnd0SW52YWxpZENsYWltRXJyb3Ige1xufVxuZXhwb3J0cy5Kd3ROb3RCZWZvcmVFcnJvciA9IEp3dE5vdEJlZm9yZUVycm9yO1xuLyoqXG4gKiBBbWF6b24gQ29nbml0byBzcGVjaWZpYyBlcnJvc1xuICovXG5jbGFzcyBDb2duaXRvSnd0SW52YWxpZEdyb3VwRXJyb3IgZXh0ZW5kcyBKd3RJbnZhbGlkQ2xhaW1FcnJvciB7XG59XG5leHBvcnRzLkNvZ25pdG9Kd3RJbnZhbGlkR3JvdXBFcnJvciA9IENvZ25pdG9Kd3RJbnZhbGlkR3JvdXBFcnJvcjtcbmNsYXNzIENvZ25pdG9Kd3RJbnZhbGlkVG9rZW5Vc2VFcnJvciBleHRlbmRzIEp3dEludmFsaWRDbGFpbUVycm9yIHtcbn1cbmV4cG9ydHMuQ29nbml0b0p3dEludmFsaWRUb2tlblVzZUVycm9yID0gQ29nbml0b0p3dEludmFsaWRUb2tlblVzZUVycm9yO1xuY2xhc3MgQ29nbml0b0p3dEludmFsaWRDbGllbnRJZEVycm9yIGV4dGVuZHMgSnd0SW52YWxpZENsYWltRXJyb3Ige1xufVxuZXhwb3J0cy5Db2duaXRvSnd0SW52YWxpZENsaWVudElkRXJyb3IgPSBDb2duaXRvSnd0SW52YWxpZENsaWVudElkRXJyb3I7XG4vKipcbiAqIEFTTi4xIGVycm9yc1xuICovXG5jbGFzcyBBc24xRGVjb2RpbmdFcnJvciBleHRlbmRzIEp3dEJhc2VFcnJvciB7XG59XG5leHBvcnRzLkFzbjFEZWNvZGluZ0Vycm9yID0gQXNuMURlY29kaW5nRXJyb3I7XG4vKipcbiAqIEpXSyBlcnJvcnNcbiAqL1xuY2xhc3MgSndrc1ZhbGlkYXRpb25FcnJvciBleHRlbmRzIEp3dEJhc2VFcnJvciB7XG59XG5leHBvcnRzLkp3a3NWYWxpZGF0aW9uRXJyb3IgPSBKd2tzVmFsaWRhdGlvbkVycm9yO1xuY2xhc3MgSndrVmFsaWRhdGlvbkVycm9yIGV4dGVuZHMgSnd0QmFzZUVycm9yIHtcbn1cbmV4cG9ydHMuSndrVmFsaWRhdGlvbkVycm9yID0gSndrVmFsaWRhdGlvbkVycm9yO1xuY2xhc3MgSnd0V2l0aG91dFZhbGlkS2lkRXJyb3IgZXh0ZW5kcyBKd3RCYXNlRXJyb3Ige1xufVxuZXhwb3J0cy5Kd3RXaXRob3V0VmFsaWRLaWRFcnJvciA9IEp3dFdpdGhvdXRWYWxpZEtpZEVycm9yO1xuY2xhc3MgS2lkTm90Rm91bmRJbkp3a3NFcnJvciBleHRlbmRzIEp3dEJhc2VFcnJvciB7XG59XG5leHBvcnRzLktpZE5vdEZvdW5kSW5Kd2tzRXJyb3IgPSBLaWROb3RGb3VuZEluSndrc0Vycm9yO1xuY2xhc3MgV2FpdFBlcmlvZE5vdFlldEVuZGVkSndrRXJyb3IgZXh0ZW5kcyBKd3RCYXNlRXJyb3Ige1xufVxuZXhwb3J0cy5XYWl0UGVyaW9kTm90WWV0RW5kZWRKd2tFcnJvciA9IFdhaXRQZXJpb2ROb3RZZXRFbmRlZEp3a0Vycm9yO1xuY2xhc3MgSndrc05vdEF2YWlsYWJsZUluQ2FjaGVFcnJvciBleHRlbmRzIEp3dEJhc2VFcnJvciB7XG59XG5leHBvcnRzLkp3a3NOb3RBdmFpbGFibGVJbkNhY2hlRXJyb3IgPSBKd2tzTm90QXZhaWxhYmxlSW5DYWNoZUVycm9yO1xuY2xhc3MgSndrSW52YWxpZFVzZUVycm9yIGV4dGVuZHMgRmFpbGVkQXNzZXJ0aW9uRXJyb3Ige1xufVxuZXhwb3J0cy5Kd2tJbnZhbGlkVXNlRXJyb3IgPSBKd2tJbnZhbGlkVXNlRXJyb3I7XG5jbGFzcyBKd2tJbnZhbGlkS3R5RXJyb3IgZXh0ZW5kcyBGYWlsZWRBc3NlcnRpb25FcnJvciB7XG59XG5leHBvcnRzLkp3a0ludmFsaWRLdHlFcnJvciA9IEp3a0ludmFsaWRLdHlFcnJvcjtcbi8qKlxuICogSFRUUFMgZmV0Y2ggZXJyb3JzXG4gKi9cbmNsYXNzIEZldGNoRXJyb3IgZXh0ZW5kcyBKd3RCYXNlRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKHVyaSwgbXNnKSB7XG4gICAgICAgIHN1cGVyKGBGYWlsZWQgdG8gZmV0Y2ggJHt1cml9OiAke21zZ31gKTtcbiAgICB9XG59XG5leHBvcnRzLkZldGNoRXJyb3IgPSBGZXRjaEVycm9yO1xuY2xhc3MgTm9uUmV0cnlhYmxlRmV0Y2hFcnJvciBleHRlbmRzIEZldGNoRXJyb3Ige1xufVxuZXhwb3J0cy5Ob25SZXRyeWFibGVGZXRjaEVycm9yID0gTm9uUmV0cnlhYmxlRmV0Y2hFcnJvcjtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IEFtYXpvbi5jb20sIEluYy4gb3IgaXRzIGFmZmlsaWF0ZXMuIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4vLyBTUERYLUxpY2Vuc2UtSWRlbnRpZmllcjogQXBhY2hlLTIuMFxuLy9cbi8vIFV0aWxpdGllcyBmb3IgZmV0Y2hpbmcgdGhlIEpXS1MgVVJJLCB0byBnZXQgdGhlIHB1YmxpYyBrZXlzIHdpdGggd2hpY2ggdG8gdmVyaWZ5IEpXVHNcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbmV4cG9ydHMuZmV0Y2hKc29uID0gZXhwb3J0cy5TaW1wbGVKc29uRmV0Y2hlciA9IHZvaWQgMDtcbmNvbnN0IGh0dHBzXzEgPSByZXF1aXJlKFwiaHR0cHNcIik7XG5jb25zdCBzdHJlYW1fMSA9IHJlcXVpcmUoXCJzdHJlYW1cIik7XG5jb25zdCB1dGlsXzEgPSByZXF1aXJlKFwidXRpbFwiKTtcbmNvbnN0IHNhZmVfanNvbl9wYXJzZV9qc18xID0gcmVxdWlyZShcIi4vc2FmZS1qc29uLXBhcnNlLmpzXCIpO1xuY29uc3QgZXJyb3JfanNfMSA9IHJlcXVpcmUoXCIuL2Vycm9yLmpzXCIpO1xuLyoqXG4gKiBIVFRQUyBGZXRjaGVyIGZvciBVUklzIHdpdGggSlNPTiBib2R5XG4gKlxuICogQHBhcmFtIGRlZmF1bHRSZXF1ZXN0T3B0aW9ucyAtIFRoZSBkZWZhdWx0IFJlcXVlc3RPcHRpb25zIHRvIHVzZSBvbiBpbmRpdmlkdWFsIEhUVFBTIHJlcXVlc3RzXG4gKi9cbmNsYXNzIFNpbXBsZUpzb25GZXRjaGVyIHtcbiAgICBjb25zdHJ1Y3Rvcihwcm9wcykge1xuICAgICAgICB0aGlzLmRlZmF1bHRSZXF1ZXN0T3B0aW9ucyA9IHtcbiAgICAgICAgICAgIHRpbWVvdXQ6IDUwMCxcbiAgICAgICAgICAgIHJlc3BvbnNlVGltZW91dDogMTUwMCxcbiAgICAgICAgICAgIC4uLnByb3BzPy5kZWZhdWx0UmVxdWVzdE9wdGlvbnMsXG4gICAgICAgIH07XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEV4ZWN1dGUgYSBIVFRQUyByZXF1ZXN0ICh3aXRoIDEgaW1tZWRpYXRlIHJldHJ5IGluIGNhc2Ugb2YgZXJyb3JzKVxuICAgICAqIEBwYXJhbSB1cmkgLSBUaGUgVVJJXG4gICAgICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gVGhlIFJlcXVlc3RPcHRpb25zIHRvIHVzZVxuICAgICAqIEBwYXJhbSBkYXRhIC0gRGF0YSB0byBzZW5kIHRvIHRoZSBVUkkgKGUuZy4gUE9TVCBkYXRhKVxuICAgICAqIEByZXR1cm5zIC0gVGhlIHJlc3BvbnNlIGFzIHBhcnNlZCBKU09OXG4gICAgICovXG4gICAgYXN5bmMgZmV0Y2godXJpLCByZXF1ZXN0T3B0aW9ucywgZGF0YSkge1xuICAgICAgICByZXF1ZXN0T3B0aW9ucyA9IHsgLi4udGhpcy5kZWZhdWx0UmVxdWVzdE9wdGlvbnMsIC4uLnJlcXVlc3RPcHRpb25zIH07XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgZmV0Y2hKc29uKHVyaSwgcmVxdWVzdE9wdGlvbnMsIGRhdGEpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgIGlmIChlcnIgaW5zdGFuY2VvZiBlcnJvcl9qc18xLk5vblJldHJ5YWJsZUZldGNoRXJyb3IpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBSZXRyeSBvbmNlLCBpbW1lZGlhdGVseVxuICAgICAgICAgICAgcmV0dXJuIGZldGNoSnNvbih1cmksIHJlcXVlc3RPcHRpb25zLCBkYXRhKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbmV4cG9ydHMuU2ltcGxlSnNvbkZldGNoZXIgPSBTaW1wbGVKc29uRmV0Y2hlcjtcbi8qKlxuICogRXhlY3V0ZSBhIEhUVFBTIHJlcXVlc3RcbiAqIEBwYXJhbSB1cmkgLSBUaGUgVVJJXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBUaGUgUmVxdWVzdE9wdGlvbnMgdG8gdXNlXG4gKiBAcGFyYW0gZGF0YSAtIERhdGEgdG8gc2VuZCB0byB0aGUgVVJJIChlLmcuIFBPU1QgZGF0YSlcbiAqIEByZXR1cm5zIC0gVGhlIHJlc3BvbnNlIGFzIHBhcnNlZCBKU09OXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGZldGNoSnNvbih1cmksIHJlcXVlc3RPcHRpb25zLCBkYXRhKSB7XG4gICAgbGV0IHJlc3BvbnNlVGltZW91dDtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICBjb25zdCByZXEgPSAoMCwgaHR0cHNfMS5yZXF1ZXN0KSh1cmksIHtcbiAgICAgICAgICAgIG1ldGhvZDogXCJHRVRcIixcbiAgICAgICAgICAgIC4uLnJlcXVlc3RPcHRpb25zLFxuICAgICAgICB9LCAocmVzcG9uc2UpID0+IHtcbiAgICAgICAgICAgIC8vIENhcHR1cmUgcmVzcG9uc2UgZGF0YVxuICAgICAgICAgICAgLy8gQHR5cGVzL25vZGUgaXMgaW5jb21wbGV0ZSBzbyBjYXN0IHRvIGFueVxuICAgICAgICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEB0eXBlc2NyaXB0LWVzbGludC9uby1leHBsaWNpdC1hbnlcbiAgICAgICAgICAgIHN0cmVhbV8xLnBpcGVsaW5lKFtcbiAgICAgICAgICAgICAgICByZXNwb25zZSxcbiAgICAgICAgICAgICAgICBnZXRKc29uRGVzdGluYXRpb24odXJpLCByZXNwb25zZS5zdGF0dXNDb2RlLCByZXNwb25zZS5oZWFkZXJzKSxcbiAgICAgICAgICAgIF0sIGRvbmUpO1xuICAgICAgICB9KTtcbiAgICAgICAgaWYgKHJlcXVlc3RPcHRpb25zPy5yZXNwb25zZVRpbWVvdXQpIHtcbiAgICAgICAgICAgIHJlc3BvbnNlVGltZW91dCA9IHNldFRpbWVvdXQoKCkgPT4gZG9uZShuZXcgZXJyb3JfanNfMS5GZXRjaEVycm9yKHVyaSwgYFJlc3BvbnNlIHRpbWUtb3V0IChhZnRlciAke3JlcXVlc3RPcHRpb25zLnJlc3BvbnNlVGltZW91dH0gbXMuKWApKSwgcmVxdWVzdE9wdGlvbnMucmVzcG9uc2VUaW1lb3V0KTtcbiAgICAgICAgICAgIHJlc3BvbnNlVGltZW91dC51bnJlZigpOyAvLyBEb24ndCBibG9jayBOb2RlIGZyb20gZXhpdGluZ1xuICAgICAgICB9XG4gICAgICAgIGZ1bmN0aW9uIGRvbmUoLi4uYXJncykge1xuICAgICAgICAgICAgaWYgKHJlc3BvbnNlVGltZW91dClcbiAgICAgICAgICAgICAgICBjbGVhclRpbWVvdXQocmVzcG9uc2VUaW1lb3V0KTtcbiAgICAgICAgICAgIGlmIChhcmdzWzBdID09IG51bGwpIHtcbiAgICAgICAgICAgICAgICByZXNvbHZlKGFyZ3NbMV0pO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIEluIGNhc2Ugb2YgZXJyb3JzLCBsZXQgdGhlIEFnZW50IChpZiBhbnkpIGtub3cgdG8gYWJhbmRvbiB0aGUgc29ja2V0XG4gICAgICAgICAgICAvLyBUaGlzIGlzIHByb2JhYmx5IGJlc3QsIGJlY2F1c2UgdGhlIHNvY2tldCBtYXkgaGF2ZSBiZWNvbWUgc3RhbGVcbiAgICAgICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgICAgICAgICByZXEuc29ja2V0Py5lbWl0KFwiYWdlbnRSZW1vdmVcIik7XG4gICAgICAgICAgICAvLyBUdXJuIGVycm9yIGludG8gRmV0Y2hFcnJvciBzbyB0aGUgVVJJIGlzIG5pY2VseSBjYXB0dXJlZCBpbiB0aGUgbWVzc2FnZVxuICAgICAgICAgICAgbGV0IGVycm9yID0gYXJnc1swXTtcbiAgICAgICAgICAgIGlmICghKGVycm9yIGluc3RhbmNlb2YgZXJyb3JfanNfMS5GZXRjaEVycm9yKSkge1xuICAgICAgICAgICAgICAgIGVycm9yID0gbmV3IGVycm9yX2pzXzEuRmV0Y2hFcnJvcih1cmksIGVycm9yLm1lc3NhZ2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmVxLmRlc3Ryb3koKTtcbiAgICAgICAgICAgIHJlamVjdChlcnJvcik7XG4gICAgICAgIH1cbiAgICAgICAgLy8gSGFuZGxlIGVycm9ycyB3aGlsZSBzZW5kaW5nIHJlcXVlc3RcbiAgICAgICAgcmVxLm9uKFwiZXJyb3JcIiwgZG9uZSk7XG4gICAgICAgIC8vIFNpZ25hbCBlbmQgb2YgcmVxdWVzdCAoaW5jbHVkZSBvcHRpb25hbCBkYXRhKVxuICAgICAgICByZXEuZW5kKGRhdGEpO1xuICAgIH0pO1xufVxuZXhwb3J0cy5mZXRjaEpzb24gPSBmZXRjaEpzb247XG4vKipcbiAqIEVuc3VyZXMgdGhlIEhUVFBTIHJlc3BvbnNlIGNvbnRhaW5zIHZhbGlkIEpTT05cbiAqXG4gKiBAcGFyYW0gdXJpIC0gVGhlIFVSSSB5b3Ugd2VyZSByZXF1ZXN0aW5nXG4gKiBAcGFyYW0gc3RhdHVzQ29kZSAtIFRoZSByZXNwb25zZSBzdGF0dXMgY29kZSB0byB5b3VyIEhUVFBTIHJlcXVlc3RcbiAqIEBwYXJhbSBoZWFkZXJzIC0gVGhlIHJlc3BvbnNlIGhlYWRlcnMgdG8geW91ciBIVFRQUyByZXF1ZXN0XG4gKlxuICogQHJldHVybnMgLSBBc3luYyBmdW5jdGlvbiB0aGF0IGNhbiBiZSB1c2VkIGFzIGRlc3RpbmF0aW9uIGluIGEgc3RyZWFtLnBpcGVsaW5lLCBpdCB3aWxsIHJldHVybiB0aGUgSlNPTiwgaWYgdmFsaWQsIG9yIHRocm93IGFuIGVycm9yIG90aGVyd2lzZVxuICovXG5mdW5jdGlvbiBnZXRKc29uRGVzdGluYXRpb24odXJpLCBzdGF0dXNDb2RlLCBoZWFkZXJzKSB7XG4gICAgcmV0dXJuIGFzeW5jIChyZXNwb25zZUl0ZXJhYmxlKSA9PiB7XG4gICAgICAgIGlmIChzdGF0dXNDb2RlID09PSA0MjkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkZldGNoRXJyb3IodXJpLCBcIlRvbyBtYW55IHJlcXVlc3RzXCIpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHN0YXR1c0NvZGUgIT09IDIwMCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuTm9uUmV0cnlhYmxlRmV0Y2hFcnJvcih1cmksIGBTdGF0dXMgY29kZSBpcyAke3N0YXR1c0NvZGV9LCBleHBlY3RlZCAyMDBgKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWhlYWRlcnNbXCJjb250ZW50LXR5cGVcIl0/LnRvTG93ZXJDYXNlKCkuc3RhcnRzV2l0aChcImFwcGxpY2F0aW9uL2pzb25cIikpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLk5vblJldHJ5YWJsZUZldGNoRXJyb3IodXJpLCBgQ29udGVudC10eXBlIGlzIFwiJHtoZWFkZXJzW1wiY29udGVudC10eXBlXCJdfVwiLCBleHBlY3RlZCBcImFwcGxpY2F0aW9uL2pzb25cImApO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGNvbGxlY3RlZCA9IFtdO1xuICAgICAgICBmb3IgYXdhaXQgKGNvbnN0IGNodW5rIG9mIHJlc3BvbnNlSXRlcmFibGUpIHtcbiAgICAgICAgICAgIGNvbGxlY3RlZC5wdXNoKGNodW5rKTtcbiAgICAgICAgfVxuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmV0dXJuICgwLCBzYWZlX2pzb25fcGFyc2VfanNfMS5zYWZlSnNvblBhcnNlKShuZXcgdXRpbF8xLlRleHREZWNvZGVyKFwidXRmOFwiLCB7IGZhdGFsOiB0cnVlLCBpZ25vcmVCT006IHRydWUgfSkuZGVjb2RlKEJ1ZmZlci5jb25jYXQoY29sbGVjdGVkKSkpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLk5vblJldHJ5YWJsZUZldGNoRXJyb3IodXJpLCBlcnIpO1xuICAgICAgICB9XG4gICAgfTtcbn1cbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IEFtYXpvbi5jb20sIEluYy4gb3IgaXRzIGFmZmlsaWF0ZXMuIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4vLyBTUERYLUxpY2Vuc2UtSWRlbnRpZmllcjogQXBhY2hlLTIuMFxuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xuZXhwb3J0cy5Db2duaXRvSnd0VmVyaWZpZXIgPSBleHBvcnRzLkp3dFJzYVZlcmlmaWVyID0gdm9pZCAwO1xudmFyIGp3dF9yc2FfanNfMSA9IHJlcXVpcmUoXCIuL2p3dC1yc2EuanNcIik7XG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJKd3RSc2FWZXJpZmllclwiLCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZnVuY3Rpb24gKCkgeyByZXR1cm4gand0X3JzYV9qc18xLkp3dFJzYVZlcmlmaWVyOyB9IH0pO1xudmFyIGNvZ25pdG9fdmVyaWZpZXJfanNfMSA9IHJlcXVpcmUoXCIuL2NvZ25pdG8tdmVyaWZpZXIuanNcIik7XG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJDb2duaXRvSnd0VmVyaWZpZXJcIiwgeyBlbnVtZXJhYmxlOiB0cnVlLCBnZXQ6IGZ1bmN0aW9uICgpIHsgcmV0dXJuIGNvZ25pdG9fdmVyaWZpZXJfanNfMS5Db2duaXRvSnd0VmVyaWZpZXI7IH0gfSk7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCBBbWF6b24uY29tLCBJbmMuIG9yIGl0cyBhZmZpbGlhdGVzLiBBbGwgUmlnaHRzIFJlc2VydmVkLlxuLy8gU1BEWC1MaWNlbnNlLUlkZW50aWZpZXI6IEFwYWNoZS0yLjBcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbmV4cG9ydHMuU2ltcGxlSndrc0NhY2hlID0gZXhwb3J0cy5TaW1wbGVQZW5hbHR5Qm94ID0gZXhwb3J0cy5pc0p3ayA9IGV4cG9ydHMuaXNKd2tzID0gZXhwb3J0cy5hc3NlcnRJc0p3ayA9IGV4cG9ydHMuYXNzZXJ0SXNKd2tzID0gZXhwb3J0cy5mZXRjaEp3ayA9IGV4cG9ydHMuZmV0Y2hKd2tzID0gdm9pZCAwO1xuY29uc3QgaHR0cHNfanNfMSA9IHJlcXVpcmUoXCIuL2h0dHBzLmpzXCIpO1xuY29uc3Qgc2FmZV9qc29uX3BhcnNlX2pzXzEgPSByZXF1aXJlKFwiLi9zYWZlLWpzb24tcGFyc2UuanNcIik7XG5jb25zdCBlcnJvcl9qc18xID0gcmVxdWlyZShcIi4vZXJyb3IuanNcIik7XG5jb25zdCBvcHRpb25hbEp3a0ZpZWxkTmFtZXMgPSBbXG4gICAgXCJhbGdcIiwgLy8gaHR0cHM6Ly9kYXRhdHJhY2tlci5pZXRmLm9yZy9kb2MvaHRtbC9yZmM3NTE3I3NlY3Rpb24tNC40XG5dO1xuY29uc3QgbWFuZGF0b3J5SndrRmllbGROYW1lcyA9IFtcbiAgICBcImVcIixcbiAgICBcImtpZFwiLFxuICAgIFwia3R5XCIsXG4gICAgXCJuXCIsXG4gICAgXCJ1c2VcIiwgLy8gaHR0cHM6Ly9kYXRhdHJhY2tlci5pZXRmLm9yZy9kb2MvaHRtbC9yZmM3NTE3I3NlY3Rpb24tNC4yIE5PVEU6IGNvbnNpZGVyZWQgbWFuZGF0b3J5IGJ5IHRoaXMgbGlicmFyeVxuXTtcbmFzeW5jIGZ1bmN0aW9uIGZldGNoSndrcyhqd2tzVXJpKSB7XG4gICAgY29uc3QgandrcyA9IGF3YWl0ICgwLCBodHRwc19qc18xLmZldGNoSnNvbikoandrc1VyaSk7XG4gICAgYXNzZXJ0SXNKd2tzKGp3a3MpO1xuICAgIHJldHVybiBqd2tzO1xufVxuZXhwb3J0cy5mZXRjaEp3a3MgPSBmZXRjaEp3a3M7XG5hc3luYyBmdW5jdGlvbiBmZXRjaEp3ayhqd2tzVXJpLCBkZWNvbXBvc2VkSnd0KSB7XG4gICAgaWYgKCFkZWNvbXBvc2VkSnd0LmhlYWRlci5raWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSnd0V2l0aG91dFZhbGlkS2lkRXJyb3IoXCJKV1QgaGVhZGVyIGRvZXMgbm90IGhhdmUgdmFsaWQga2lkIGNsYWltXCIpO1xuICAgIH1cbiAgICBjb25zdCBqd2sgPSAoYXdhaXQgZmV0Y2hKd2tzKGp3a3NVcmkpKS5rZXlzLmZpbmQoKGtleSkgPT4ga2V5LmtpZCA9PT0gZGVjb21wb3NlZEp3dC5oZWFkZXIua2lkKTtcbiAgICBpZiAoIWp3aykge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5LaWROb3RGb3VuZEluSndrc0Vycm9yKGBKV0sgZm9yIGtpZCBcIiR7ZGVjb21wb3NlZEp3dC5oZWFkZXIua2lkfVwiIG5vdCBmb3VuZCBpbiB0aGUgSldLU2ApO1xuICAgIH1cbiAgICByZXR1cm4gandrO1xufVxuZXhwb3J0cy5mZXRjaEp3ayA9IGZldGNoSndrO1xuZnVuY3Rpb24gYXNzZXJ0SXNKd2tzKGp3a3MpIHtcbiAgICBpZiAoIWp3a3MpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSndrc1ZhbGlkYXRpb25FcnJvcihcIkpXS1MgZW1wdHlcIik7XG4gICAgfVxuICAgIGlmICghKDAsIHNhZmVfanNvbl9wYXJzZV9qc18xLmlzSnNvbk9iamVjdCkoandrcykpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSndrc1ZhbGlkYXRpb25FcnJvcihcIkpXS1Mgc2hvdWxkIGJlIGFuIG9iamVjdFwiKTtcbiAgICB9XG4gICAgaWYgKCFPYmplY3Qua2V5cyhqd2tzKS5pbmNsdWRlcyhcImtleXNcIikpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSndrc1ZhbGlkYXRpb25FcnJvcihcIkpXS1MgZG9lcyBub3QgaW5jbHVkZSBrZXlzXCIpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkoandrcy5rZXlzKSkge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd2tzVmFsaWRhdGlvbkVycm9yKFwiSldLUyBrZXlzIHNob3VsZCBiZSBhbiBhcnJheVwiKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCBqd2sgb2Ygandrcy5rZXlzKSB7XG4gICAgICAgIGFzc2VydElzSndrKGp3ayk7XG4gICAgfVxufVxuZXhwb3J0cy5hc3NlcnRJc0p3a3MgPSBhc3NlcnRJc0p3a3M7XG5mdW5jdGlvbiBhc3NlcnRJc0p3ayhqd2spIHtcbiAgICBpZiAoIWp3aykge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd2tWYWxpZGF0aW9uRXJyb3IoXCJKV0sgZW1wdHlcIik7XG4gICAgfVxuICAgIGlmICghKDAsIHNhZmVfanNvbl9wYXJzZV9qc18xLmlzSnNvbk9iamVjdCkoandrKSkge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd2tWYWxpZGF0aW9uRXJyb3IoXCJKV0sgc2hvdWxkIGJlIGFuIG9iamVjdFwiKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCBmaWVsZCBvZiBtYW5kYXRvcnlKd2tGaWVsZE5hbWVzKSB7XG4gICAgICAgIC8vIGRpc2FibGUgZXNsaW50IHJ1bGUgYmVjYXVzZSBgZmllbGRgIGlzIHRydXN0ZWRcbiAgICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIHNlY3VyaXR5L2RldGVjdC1vYmplY3QtaW5qZWN0aW9uXG4gICAgICAgIGlmICh0eXBlb2YgandrW2ZpZWxkXSAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSndrVmFsaWRhdGlvbkVycm9yKGBKV0sgJHtmaWVsZH0gc2hvdWxkIGJlIGEgc3RyaW5nYCk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgZm9yIChjb25zdCBmaWVsZCBvZiBvcHRpb25hbEp3a0ZpZWxkTmFtZXMpIHtcbiAgICAgICAgLy8gZGlzYWJsZSBlc2xpbnQgcnVsZSBiZWNhdXNlIGBmaWVsZGAgaXMgdHJ1c3RlZFxuICAgICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgc2VjdXJpdHkvZGV0ZWN0LW9iamVjdC1pbmplY3Rpb25cbiAgICAgICAgaWYgKGZpZWxkIGluIGp3ayAmJiB0eXBlb2YgandrW2ZpZWxkXSAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSndrVmFsaWRhdGlvbkVycm9yKGBKV0sgJHtmaWVsZH0gc2hvdWxkIGJlIGEgc3RyaW5nYCk7XG4gICAgICAgIH1cbiAgICB9XG59XG5leHBvcnRzLmFzc2VydElzSndrID0gYXNzZXJ0SXNKd2s7XG5mdW5jdGlvbiBpc0p3a3Moandrcykge1xuICAgIHRyeSB7XG4gICAgICAgIGFzc2VydElzSndrcyhqd2tzKTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbn1cbmV4cG9ydHMuaXNKd2tzID0gaXNKd2tzO1xuZnVuY3Rpb24gaXNKd2soandrKSB7XG4gICAgdHJ5IHtcbiAgICAgICAgYXNzZXJ0SXNKd2soandrKTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbn1cbmV4cG9ydHMuaXNKd2sgPSBpc0p3aztcbmNsYXNzIFNpbXBsZVBlbmFsdHlCb3gge1xuICAgIGNvbnN0cnVjdG9yKHByb3BzKSB7XG4gICAgICAgIHRoaXMud2FpdGluZ1VyaXMgPSBuZXcgTWFwKCk7XG4gICAgICAgIHRoaXMud2FpdFNlY29uZHMgPSBwcm9wcz8ud2FpdFNlY29uZHMgPz8gMTA7XG4gICAgfVxuICAgIGFzeW5jIHdhaXQoandrc1VyaSkge1xuICAgICAgICAvLyBTaW1wbGVQZW5hbHR5Qm94IGRvZXMgbm90IGFjdHVhbGx5IHdhaXQgYnV0IGJsdW50bHkgdGhyb3dzIGFuIGVycm9yXG4gICAgICAgIC8vIEFueSB3YWl0aW5nIGFuZCByZXRyaWVzIGFyZSBleHBlY3RlZCB0byBiZSBkb25lIHVwc3RyZWFtIChlLmcuIGluIHRoZSBicm93c2VyIC8gYXBwKVxuICAgICAgICBpZiAodGhpcy53YWl0aW5nVXJpcy5oYXMoandrc1VyaSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLldhaXRQZXJpb2ROb3RZZXRFbmRlZEp3a0Vycm9yKFwiTm90IGFsbG93ZWQgdG8gZmV0Y2ggSldLUyB5ZXQsIHN0aWxsIHdhaXRpbmcgZm9yIGJhY2sgb2ZmIHBlcmlvZCB0byBlbmRcIik7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmVsZWFzZShqd2tzVXJpKSB7XG4gICAgICAgIGNvbnN0IGkgPSB0aGlzLndhaXRpbmdVcmlzLmdldChqd2tzVXJpKTtcbiAgICAgICAgaWYgKGkpIHtcbiAgICAgICAgICAgIGNsZWFyVGltZW91dChpKTtcbiAgICAgICAgICAgIHRoaXMud2FpdGluZ1VyaXMuZGVsZXRlKGp3a3NVcmkpO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJlZ2lzdGVyRmFpbGVkQXR0ZW1wdChqd2tzVXJpKSB7XG4gICAgICAgIGNvbnN0IGkgPSBzZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMud2FpdGluZ1VyaXMuZGVsZXRlKGp3a3NVcmkpO1xuICAgICAgICB9LCB0aGlzLndhaXRTZWNvbmRzICogMTAwMCkudW5yZWYoKTtcbiAgICAgICAgdGhpcy53YWl0aW5nVXJpcy5zZXQoandrc1VyaSwgaSk7XG4gICAgfVxuICAgIHJlZ2lzdGVyU3VjY2Vzc2Z1bEF0dGVtcHQoandrc1VyaSkge1xuICAgICAgICB0aGlzLnJlbGVhc2Uoandrc1VyaSk7XG4gICAgfVxufVxuZXhwb3J0cy5TaW1wbGVQZW5hbHR5Qm94ID0gU2ltcGxlUGVuYWx0eUJveDtcbmNsYXNzIFNpbXBsZUp3a3NDYWNoZSB7XG4gICAgY29uc3RydWN0b3IocHJvcHMpIHtcbiAgICAgICAgdGhpcy5qd2tzQ2FjaGUgPSBuZXcgTWFwKCk7XG4gICAgICAgIHRoaXMuZmV0Y2hpbmdKd2tzID0gbmV3IE1hcCgpO1xuICAgICAgICB0aGlzLnBlbmFsdHlCb3ggPSBwcm9wcz8ucGVuYWx0eUJveCA/PyBuZXcgU2ltcGxlUGVuYWx0eUJveCgpO1xuICAgICAgICB0aGlzLmZldGNoZXIgPSBwcm9wcz8uZmV0Y2hlciA/PyBuZXcgaHR0cHNfanNfMS5TaW1wbGVKc29uRmV0Y2hlcigpO1xuICAgIH1cbiAgICBhZGRKd2tzKGp3a3NVcmksIGp3a3MpIHtcbiAgICAgICAgdGhpcy5qd2tzQ2FjaGUuc2V0KGp3a3NVcmksIGp3a3MpO1xuICAgIH1cbiAgICBhc3luYyBnZXRKd2tzKGp3a3NVcmkpIHtcbiAgICAgICAgY29uc3QgZXhpc3RpbmdGZXRjaCA9IHRoaXMuZmV0Y2hpbmdKd2tzLmdldChqd2tzVXJpKTtcbiAgICAgICAgaWYgKGV4aXN0aW5nRmV0Y2gpIHtcbiAgICAgICAgICAgIHJldHVybiBleGlzdGluZ0ZldGNoO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGp3a3NQcm9taXNlID0gdGhpcy5mZXRjaGVyLmZldGNoKGp3a3NVcmkpLnRoZW4oKHJlcykgPT4ge1xuICAgICAgICAgICAgYXNzZXJ0SXNKd2tzKHJlcyk7XG4gICAgICAgICAgICByZXR1cm4gcmVzO1xuICAgICAgICB9KTtcbiAgICAgICAgdGhpcy5mZXRjaGluZ0p3a3Muc2V0KGp3a3NVcmksIGp3a3NQcm9taXNlKTtcbiAgICAgICAgbGV0IGp3a3M7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBqd2tzID0gYXdhaXQgandrc1Byb21pc2U7XG4gICAgICAgIH1cbiAgICAgICAgZmluYWxseSB7XG4gICAgICAgICAgICB0aGlzLmZldGNoaW5nSndrcy5kZWxldGUoandrc1VyaSk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5qd2tzQ2FjaGUuc2V0KGp3a3NVcmksIGp3a3MpO1xuICAgICAgICByZXR1cm4gandrcztcbiAgICB9XG4gICAgZ2V0Q2FjaGVkSndrKGp3a3NVcmksIGRlY29tcG9zZWRKd3QpIHtcbiAgICAgICAgaWYgKHR5cGVvZiBkZWNvbXBvc2VkSnd0LmhlYWRlci5raWQgIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFdpdGhvdXRWYWxpZEtpZEVycm9yKFwiSldUIGhlYWRlciBkb2VzIG5vdCBoYXZlIHZhbGlkIGtpZCBjbGFpbVwiKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMuandrc0NhY2hlLmhhcyhqd2tzVXJpKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSndrc05vdEF2YWlsYWJsZUluQ2FjaGVFcnJvcihgSldLUyBmb3IgdXJpICR7andrc1VyaX0gbm90IHlldCBhdmFpbGFibGUgaW4gY2FjaGVgKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBqd2sgPSB0aGlzLmp3a3NDYWNoZVxuICAgICAgICAgICAgLmdldChqd2tzVXJpKVxuICAgICAgICAgICAgLmtleXMuZmluZCgoa2V5KSA9PiBrZXkua2lkID09PSBkZWNvbXBvc2VkSnd0LmhlYWRlci5raWQpO1xuICAgICAgICBpZiAoIWp3aykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuS2lkTm90Rm91bmRJbkp3a3NFcnJvcihgSldLIGZvciBraWQgJHtkZWNvbXBvc2VkSnd0LmhlYWRlci5raWR9IG5vdCBmb3VuZCBpbiB0aGUgSldLU2ApO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd2s7XG4gICAgfVxuICAgIGFzeW5jIGdldEp3ayhqd2tzVXJpLCBkZWNvbXBvc2VkSnd0KSB7XG4gICAgICAgIGlmICh0eXBlb2YgZGVjb21wb3NlZEp3dC5oZWFkZXIua2lkICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3RXaXRob3V0VmFsaWRLaWRFcnJvcihcIkpXVCBoZWFkZXIgZG9lcyBub3QgaGF2ZSB2YWxpZCBraWQgY2xhaW1cIik7XG4gICAgICAgIH1cbiAgICAgICAgLy8gVHJ5IHRvIGdldCBKV0sgZnJvbSBjYWNoZTpcbiAgICAgICAgbGV0IGp3ayA9IHRoaXMuandrc0NhY2hlXG4gICAgICAgICAgICAuZ2V0KGp3a3NVcmkpXG4gICAgICAgICAgICA/LmtleXMuZmluZCgoa2V5KSA9PiBrZXkua2lkID09PSBkZWNvbXBvc2VkSnd0LmhlYWRlci5raWQpO1xuICAgICAgICBpZiAoandrKSB7XG4gICAgICAgICAgICByZXR1cm4gandrO1xuICAgICAgICB9XG4gICAgICAgIC8vIEF3YWl0IGFueSB3YWl0IHBlcmlvZCB0aGF0IGlzIGN1cnJlbnRseSBpbiBlZmZlY3RcbiAgICAgICAgLy8gVGhpcyBwcmV2ZW50cyB1cyBmcm9tIGZsb29kaW5nIHRoZSBKV0tTIFVSSSB3aXRoIHJlcXVlc3RzXG4gICAgICAgIGF3YWl0IHRoaXMucGVuYWx0eUJveC53YWl0KGp3a3NVcmksIGRlY29tcG9zZWRKd3QuaGVhZGVyLmtpZCk7XG4gICAgICAgIC8vIEZldGNoIHRoZSBKV0tTIGFuZCAodHJ5IHRvKSBsb2NhdGUgdGhlIEpXS1xuICAgICAgICBjb25zdCBqd2tzID0gYXdhaXQgdGhpcy5nZXRKd2tzKGp3a3NVcmkpO1xuICAgICAgICBqd2sgPSBqd2tzLmtleXMuZmluZCgoa2V5KSA9PiBrZXkua2lkID09PSBkZWNvbXBvc2VkSnd0LmhlYWRlci5raWQpO1xuICAgICAgICAvLyBJZiB0aGUgSldLIGNvdWxkIG5vdCBiZSBsb2NhdGVkLCBzb21lb25lIG1pZ2h0IGJlIG1lc3NpbmcgYXJvdW5kIHdpdGggdXNcbiAgICAgICAgLy8gUmVnaXN0ZXIgdGhlIGZhaWxlZCBhdHRlbXB0IHdpdGggdGhlIHBlbmFsdHlCb3gsIHNvIGl0IGNhbiBlbmZvcmNlIGEgd2FpdCBwZXJpb2RcbiAgICAgICAgLy8gYmVmb3JlIHRyeWluZyBhZ2FpbiBuZXh0IHRpbWUgKGluc3RlYWQgb2YgZmxvb2RpbmcgdGhlIEpXS1MgVVJJIHdpdGggcmVxdWVzdHMpXG4gICAgICAgIGlmICghandrKSB7XG4gICAgICAgICAgICB0aGlzLnBlbmFsdHlCb3gucmVnaXN0ZXJGYWlsZWRBdHRlbXB0KGp3a3NVcmksIGRlY29tcG9zZWRKd3QuaGVhZGVyLmtpZCk7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5LaWROb3RGb3VuZEluSndrc0Vycm9yKGBKV0sgZm9yIGtpZCBcIiR7ZGVjb21wb3NlZEp3dC5oZWFkZXIua2lkfVwiIG5vdCBmb3VuZCBpbiB0aGUgSldLU2ApO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdGhpcy5wZW5hbHR5Qm94LnJlZ2lzdGVyU3VjY2Vzc2Z1bEF0dGVtcHQoandrc1VyaSwgZGVjb21wb3NlZEp3dC5oZWFkZXIua2lkKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandrO1xuICAgIH1cbn1cbmV4cG9ydHMuU2ltcGxlSndrc0NhY2hlID0gU2ltcGxlSndrc0NhY2hlO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgQW1hem9uLmNvbSwgSW5jLiBvciBpdHMgYWZmaWxpYXRlcy4gQWxsIFJpZ2h0cyBSZXNlcnZlZC5cbi8vIFNQRFgtTGljZW5zZS1JZGVudGlmaWVyOiBBcGFjaGUtMi4wXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG5leHBvcnRzLktleU9iamVjdENhY2hlID0gZXhwb3J0cy50cmFuc2Zvcm1Kd2tUb0tleU9iamVjdCA9IGV4cG9ydHMuSnd0UnNhVmVyaWZpZXIgPSBleHBvcnRzLkp3dFJzYVZlcmlmaWVyQmFzZSA9IGV4cG9ydHMudmVyaWZ5Snd0U3luYyA9IGV4cG9ydHMudmVyaWZ5Snd0ID0gZXhwb3J0cy5Kd3RTaWduYXR1cmVBbGdvcml0aG1zID0gdm9pZCAwO1xuY29uc3QgY3J5cHRvXzEgPSByZXF1aXJlKFwiY3J5cHRvXCIpO1xuY29uc3QgdXJsXzEgPSByZXF1aXJlKFwidXJsXCIpO1xuY29uc3QgcGF0aF8xID0gcmVxdWlyZShcInBhdGhcIik7XG5jb25zdCBqd2tfanNfMSA9IHJlcXVpcmUoXCIuL2p3ay5qc1wiKTtcbmNvbnN0IGFzbjFfanNfMSA9IHJlcXVpcmUoXCIuL2FzbjEuanNcIik7XG5jb25zdCBhc3NlcnRfanNfMSA9IHJlcXVpcmUoXCIuL2Fzc2VydC5qc1wiKTtcbmNvbnN0IGp3dF9qc18xID0gcmVxdWlyZShcIi4vand0LmpzXCIpO1xuY29uc3QgZXJyb3JfanNfMSA9IHJlcXVpcmUoXCIuL2Vycm9yLmpzXCIpO1xuLyoqXG4gKiBFbnVtIHRvIG1hcCBzdXBwb3J0ZWQgSldUIHNpZ25hdHVyZSBhbGdvcml0aG1zIHdpdGggT3BlblNTTCBtZXNzYWdlIGRpZ2VzdCBhbGdvcml0aG0gbmFtZXNcbiAqL1xudmFyIEp3dFNpZ25hdHVyZUFsZ29yaXRobXM7XG4oZnVuY3Rpb24gKEp3dFNpZ25hdHVyZUFsZ29yaXRobXMpIHtcbiAgICBKd3RTaWduYXR1cmVBbGdvcml0aG1zW1wiUlMyNTZcIl0gPSBcIlJTQS1TSEEyNTZcIjtcbiAgICBKd3RTaWduYXR1cmVBbGdvcml0aG1zW1wiUlMzODRcIl0gPSBcIlJTQS1TSEEzODRcIjtcbiAgICBKd3RTaWduYXR1cmVBbGdvcml0aG1zW1wiUlM1MTJcIl0gPSBcIlJTQS1TSEE1MTJcIjtcbn0pKEp3dFNpZ25hdHVyZUFsZ29yaXRobXMgPSBleHBvcnRzLkp3dFNpZ25hdHVyZUFsZ29yaXRobXMgfHwgKGV4cG9ydHMuSnd0U2lnbmF0dXJlQWxnb3JpdGhtcyA9IHt9KSk7XG4vKipcbiAqIFZlcmlmeSBhIEpXVHMgc2lnbmF0dXJlIGFnYWlucyBhIEpXSy4gVGhpcyBmdW5jdGlvbiB0aHJvd3MgYW4gZXJyb3IgaWYgdGhlIEpXVCBpcyBub3QgdmFsaWRcbiAqXG4gKiBAcGFyYW0gaGVhZGVyIFRoZSBkZWNvZGVkIGFuZCBKU09OIHBhcnNlZCBKV1QgaGVhZGVyXG4gKiBAcGFyYW0gaGVhZGVyQjY0IFRoZSBKV1QgaGVhZGVyIGluIGJhc2U2NCBlbmNvZGVkIGZvcm1cbiAqIEBwYXJhbSBwYXlsb2FkIFRoZSBkZWNvZGVkIGFuZCBKU09OIHBhcnNlZCBKV1QgcGF5bG9hZFxuICogQHBhcmFtIHBheWxvYWRCNjQgVGhlIEpXVCBwYXlsb2FkIGluIGJhc2U2NCBlbmNvZGVkIGZvcm1cbiAqIEBwYXJhbSBzaWduYXR1cmVCNjQgVGhlIEpXVCBzaWduYXR1cmUgaW4gYmFzZTY0IGVuY29kZWQgZm9ybVxuICogQHBhcmFtIGp3ayBUaGUgSldLIHdpdGggd2hpY2ggdGhlIEpXVCB3YXMgc2lnbmVkXG4gKiBAcGFyYW0gandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lciBGdW5jdGlvbiB0byB0cmFuc2Zvcm0gdGhlIEpXSyBpbnRvIGEgTm9kZS5qcyBuYXRpdmUga2V5IG9iamVjdFxuICogQHJldHVybnMgdm9pZFxuICovXG5mdW5jdGlvbiB2ZXJpZnlTaWduYXR1cmVBZ2FpbnN0SndrKGhlYWRlciwgaGVhZGVyQjY0LCBwYXlsb2FkLCBwYXlsb2FkQjY0LCBzaWduYXR1cmVCNjQsIGp3aywgandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lciA9IGV4cG9ydHMudHJhbnNmb3JtSndrVG9LZXlPYmplY3QpIHtcbiAgICAvLyBDaGVjayBKV0sgdXNlXG4gICAgKDAsIGFzc2VydF9qc18xLmFzc2VydFN0cmluZ0VxdWFscykoXCJKV0sgdXNlXCIsIGp3ay51c2UsIFwic2lnXCIsIGVycm9yX2pzXzEuSndrSW52YWxpZFVzZUVycm9yKTtcbiAgICAvLyBDaGVjayBKV0sga3R5XG4gICAgKDAsIGFzc2VydF9qc18xLmFzc2VydFN0cmluZ0VxdWFscykoXCJKV0sga3R5XCIsIGp3ay5rdHksIFwiUlNBXCIsIGVycm9yX2pzXzEuSndrSW52YWxpZEt0eUVycm9yKTtcbiAgICAvLyBDaGVjayB0aGF0IEpXVCBzaWduYXR1cmUgYWxnb3JpdGhtIG1hdGNoZXMgSldLXG4gICAgaWYgKGp3ay5hbGcpIHtcbiAgICAgICAgKDAsIGFzc2VydF9qc18xLmFzc2VydFN0cmluZ0VxdWFscykoXCJKV1Qgc2lnbmF0dXJlIGFsZ29yaXRobVwiLCBoZWFkZXIuYWxnLCBqd2suYWxnLCBlcnJvcl9qc18xLkp3dEludmFsaWRTaWduYXR1cmVBbGdvcml0aG1FcnJvcik7XG4gICAgfVxuICAgIC8vIENoZWNrIEpXVCBzaWduYXR1cmUgYWxnb3JpdGhtIGlzIG9uZSBvZiBSUzI1NiwgUlMzODQsIFJTNTEyXG4gICAgKDAsIGFzc2VydF9qc18xLmFzc2VydFN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcpKFwiSldUIHNpZ25hdHVyZSBhbGdvcml0aG1cIiwgaGVhZGVyLmFsZywgW1wiUlMyNTZcIiwgXCJSUzM4NFwiLCBcIlJTNTEyXCJdLCBlcnJvcl9qc18xLkp3dEludmFsaWRTaWduYXR1cmVBbGdvcml0aG1FcnJvcik7XG4gICAgLy8gQ29udmVydCBKV0sgbW9kdWx1cyBhbmQgZXhwb25lbnQgaW50byBERVIgcHVibGljIGtleVxuICAgIGNvbnN0IHB1YmxpY0tleSA9IGp3a1RvS2V5T2JqZWN0VHJhbnNmb3JtZXIoandrLCBwYXlsb2FkLmlzcywgaGVhZGVyLmtpZCk7XG4gICAgLy8gVmVyaWZ5IHRoZSBKV1Qgc2lnbmF0dXJlXG4gICAgY29uc3QgdmFsaWQgPSAoMCwgY3J5cHRvXzEuY3JlYXRlVmVyaWZ5KShKd3RTaWduYXR1cmVBbGdvcml0aG1zW2hlYWRlci5hbGddKVxuICAgICAgICAudXBkYXRlKGAke2hlYWRlckI2NH0uJHtwYXlsb2FkQjY0fWApXG4gICAgICAgIC52ZXJpZnkocHVibGljS2V5LCBzaWduYXR1cmVCNjQsIFwiYmFzZTY0XCIpO1xuICAgIGlmICghdmFsaWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSnd0SW52YWxpZFNpZ25hdHVyZUVycm9yKFwiSW52YWxpZCBzaWduYXR1cmVcIik7XG4gICAgfVxufVxuLyoqXG4gKiBWZXJpZnkgYSBKV1QgYXN5bmNocm9ub3VzbHkgKHRodXMgYWxsb3dpbmcgZm9yIHRoZSBKV0tTIHRvIGJlIGZldGNoZWQgZnJvbSB0aGUgSldLUyBVUkkpXG4gKlxuICogQHBhcmFtIGp3dCBUaGUgSldUXG4gKiBAcGFyYW0gandrc1VyaSBUaGUgSldLUyBVUkksIHdoZXJlIHRoZSBKV0tTIGNhbiBiZSBmZXRjaGVkIGZyb21cbiAqIEBwYXJhbSBvcHRpb25zIFZlcmlmaWNhdGlvbiBvcHRpb25zXG4gKiBAcGFyYW0gandrRmV0Y2hlciBBIGZ1bmN0aW9uIHRoYXQgY2FuIGV4ZWN1dGUgdGhlIGZldGNoIG9mIHRoZSBKV0tTIGZyb20gdGhlIEpXS1MgVVJJXG4gKiBAcGFyYW0gandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lciBBIGZ1bmN0aW9uIHRoYXQgY2FuIHRyYW5zZm9ybSBhIEpXSyBpbnRvIGEgTm9kZS5qcyBuYXRpdmUga2V5IG9iamVjdFxuICogQHJldHVybnMgUHJvbWlzZSB0aGF0IHJlc29sdmVzIHRvIHRoZSBwYXlsb2FkIG9mIHRoZSBKV1TigJPigJNpZiB0aGUgSldUIGlzIHZhbGlkLCBvdGhlcndpc2UgdGhlIHByb21pc2UgcmVqZWN0c1xuICovXG5hc3luYyBmdW5jdGlvbiB2ZXJpZnlKd3Qoand0LCBqd2tzVXJpLCBvcHRpb25zLCBqd2tGZXRjaGVyLCBqd2tUb0tleU9iamVjdFRyYW5zZm9ybWVyKSB7XG4gICAgcmV0dXJuIHZlcmlmeURlY29tcG9zZWRKd3QoKDAsIGp3dF9qc18xLmRlY29tcG9zZUp3dCkoand0KSwgandrc1VyaSwgb3B0aW9ucywgandrRmV0Y2hlciwgandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lcik7XG59XG5leHBvcnRzLnZlcmlmeUp3dCA9IHZlcmlmeUp3dDtcbi8qKlxuICogVmVyaWZ5IChhc3luY2hyb25vdXNseSkgYSBKV1QgdGhhdCBpcyBhbHJlYWR5IGRlY29tcG9zZWQgKGJ5IGZ1bmN0aW9uIGBkZWNvbXBvc2VKd3RgKVxuICpcbiAqIEBwYXJhbSBkZWNvbXBvc2VkSnd0IFRoZSBkZWNvbXBvc2VkIEpXVFxuICogQHBhcmFtIGp3a3NVcmkgVGhlIEpXS1MgVVJJLCB3aGVyZSB0aGUgSldLUyBjYW4gYmUgZmV0Y2hlZCBmcm9tXG4gKiBAcGFyYW0gb3B0aW9ucyBWZXJpZmljYXRpb24gb3B0aW9uc1xuICogQHBhcmFtIGp3a0ZldGNoZXIgQSBmdW5jdGlvbiB0aGF0IGNhbiBleGVjdXRlIHRoZSBmZXRjaCBvZiB0aGUgSldLUyBmcm9tIHRoZSBKV0tTIFVSSVxuICogQHBhcmFtIGp3a1RvS2V5T2JqZWN0VHJhbnNmb3JtZXIgQSBmdW5jdGlvbiB0aGF0IGNhbiB0cmFuc2Zvcm0gYSBKV0sgaW50byBhIE5vZGUuanMgbmF0aXZlIGtleSBvYmplY3RcbiAqIEByZXR1cm5zIFByb21pc2UgdGhhdCByZXNvbHZlcyB0byB0aGUgcGF5bG9hZCBvZiB0aGUgSldU4oCT4oCTaWYgdGhlIEpXVCBpcyB2YWxpZCwgb3RoZXJ3aXNlIHRoZSBwcm9taXNlIHJlamVjdHNcbiAqL1xuYXN5bmMgZnVuY3Rpb24gdmVyaWZ5RGVjb21wb3NlZEp3dChkZWNvbXBvc2VkSnd0LCBqd2tzVXJpLCBvcHRpb25zLCBqd2tGZXRjaGVyID0gandrX2pzXzEuZmV0Y2hKd2ssIGp3a1RvS2V5T2JqZWN0VHJhbnNmb3JtZXIpIHtcbiAgICBjb25zdCB7IGhlYWRlciwgaGVhZGVyQjY0LCBwYXlsb2FkLCBwYXlsb2FkQjY0LCBzaWduYXR1cmVCNjQgfSA9IGRlY29tcG9zZWRKd3Q7XG4gICAgY29uc3QgandrID0gYXdhaXQgandrRmV0Y2hlcihqd2tzVXJpLCBkZWNvbXBvc2VkSnd0KTtcbiAgICB2ZXJpZnlTaWduYXR1cmVBZ2FpbnN0SndrKGhlYWRlciwgaGVhZGVyQjY0LCBwYXlsb2FkLCBwYXlsb2FkQjY0LCBzaWduYXR1cmVCNjQsIGp3aywgandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lcik7XG4gICAgdHJ5IHtcbiAgICAgICAgKDAsIGp3dF9qc18xLnZhbGlkYXRlSnd0RmllbGRzKShwYXlsb2FkLCBvcHRpb25zKTtcbiAgICAgICAgaWYgKG9wdGlvbnMuY3VzdG9tSnd0Q2hlY2spIHtcbiAgICAgICAgICAgIGF3YWl0IG9wdGlvbnMuY3VzdG9tSnd0Q2hlY2soeyBoZWFkZXIsIHBheWxvYWQsIGp3ayB9KTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGlmIChvcHRpb25zLmluY2x1ZGVSYXdKd3RJbkVycm9ycyAmJiBlcnIgaW5zdGFuY2VvZiBlcnJvcl9qc18xLkp3dEludmFsaWRDbGFpbUVycm9yKSB7XG4gICAgICAgICAgICB0aHJvdyBlcnIud2l0aFJhd0p3dChkZWNvbXBvc2VkSnd0KTtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBlcnI7XG4gICAgfVxuICAgIHJldHVybiBwYXlsb2FkO1xufVxuLyoqXG4gKiBWZXJpZnkgYSBKV1Qgc3luY2hyb25vdXNseSwgdXNpbmcgYSBKV0tTIG9yIEpXSyB0aGF0IGhhcyBhbHJlYWR5IGJlZW4gZmV0Y2hlZFxuICpcbiAqIEBwYXJhbSBqd3QgVGhlIEpXVFxuICogQHBhcmFtIGp3a09ySndrcyBUaGUgSldLUyB0aGF0IGluY2x1ZGVzIHRoZSByaWdodCBKV0sgKGluZGV4ZWQgYnkga2lkKS4gQWx0ZXJuYXRpdmVseSwgcHJvdmlkZSB0aGUgcmlnaHQgSldLIGRpcmVjdGx5XG4gKiBAcGFyYW0gb3B0aW9ucyBWZXJpZmljYXRpb24gb3B0aW9uc1xuICogQHBhcmFtIGp3a1RvS2V5T2JqZWN0VHJhbnNmb3JtZXIgQSBmdW5jdGlvbiB0aGF0IGNhbiB0cmFuc2Zvcm0gYSBKV0sgaW50byBhIE5vZGUuanMgbmF0aXZlIGtleSBvYmplY3RcbiAqIEByZXR1cm5zIFRoZSAoSlNPTiBwYXJzZWQpIHBheWxvYWQgb2YgdGhlIEpXVOKAk+KAk2lmIHRoZSBKV1QgaXMgdmFsaWQsIG90aGVyd2lzZSBhbiBlcnJvciBpcyB0aHJvd25cbiAqL1xuZnVuY3Rpb24gdmVyaWZ5Snd0U3luYyhqd3QsIGp3a09ySndrcywgb3B0aW9ucywgandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lcikge1xuICAgIHJldHVybiB2ZXJpZnlEZWNvbXBvc2VkSnd0U3luYygoMCwgand0X2pzXzEuZGVjb21wb3NlSnd0KShqd3QpLCBqd2tPckp3a3MsIG9wdGlvbnMsIGp3a1RvS2V5T2JqZWN0VHJhbnNmb3JtZXIpO1xufVxuZXhwb3J0cy52ZXJpZnlKd3RTeW5jID0gdmVyaWZ5Snd0U3luYztcbi8qKlxuICogVmVyaWZ5IChzeW5jaHJvbm91c2x5KSBhIEpXVCB0aGF0IGlzIGFscmVhZHkgZGVjb21wb3NlZCAoYnkgZnVuY3Rpb24gYGRlY29tcG9zZUp3dGApXG4gKlxuICogQHBhcmFtIGRlY29tcG9zZWRKd3QgVGhlIGRlY29tcG9zZWQgSldUXG4gKiBAcGFyYW0gandrT3JKd2tzIFRoZSBKV0tTIHRoYXQgaW5jbHVkZXMgdGhlIHJpZ2h0IEpXSyAoaW5kZXhlZCBieSBraWQpLiBBbHRlcm5hdGl2ZWx5LCBwcm92aWRlIHRoZSByaWdodCBKV0sgZGlyZWN0bHlcbiAqIEBwYXJhbSBvcHRpb25zIFZlcmlmaWNhdGlvbiBvcHRpb25zXG4gKiBAcGFyYW0gandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lciBBIGZ1bmN0aW9uIHRoYXQgY2FuIHRyYW5zZm9ybSBhIEpXSyBpbnRvIGEgTm9kZS5qcyBuYXRpdmUga2V5IG9iamVjdFxuICogQHJldHVybnMgVGhlIChKU09OIHBhcnNlZCkgcGF5bG9hZCBvZiB0aGUgSldU4oCT4oCTaWYgdGhlIEpXVCBpcyB2YWxpZCwgb3RoZXJ3aXNlIGFuIGVycm9yIGlzIHRocm93blxuICovXG5mdW5jdGlvbiB2ZXJpZnlEZWNvbXBvc2VkSnd0U3luYyhkZWNvbXBvc2VkSnd0LCBqd2tPckp3a3MsIG9wdGlvbnMsIGp3a1RvS2V5T2JqZWN0VHJhbnNmb3JtZXIpIHtcbiAgICBjb25zdCB7IGhlYWRlciwgaGVhZGVyQjY0LCBwYXlsb2FkLCBwYXlsb2FkQjY0LCBzaWduYXR1cmVCNjQgfSA9IGRlY29tcG9zZWRKd3Q7XG4gICAgbGV0IGp3aztcbiAgICBpZiAoKDAsIGp3a19qc18xLmlzSndrKShqd2tPckp3a3MpKSB7XG4gICAgICAgIGp3ayA9IGp3a09ySndrcztcbiAgICB9XG4gICAgZWxzZSBpZiAoKDAsIGp3a19qc18xLmlzSndrcykoandrT3JKd2tzKSkge1xuICAgICAgICBjb25zdCBsb2NhdGVkSndrID0gandrT3JKd2tzLmtleXMuZmluZCgoa2V5KSA9PiBrZXkua2lkID09PSBoZWFkZXIua2lkKTtcbiAgICAgICAgaWYgKCFsb2NhdGVkSndrKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5LaWROb3RGb3VuZEluSndrc0Vycm9yKGBKV0sgZm9yIGtpZCAke2hlYWRlci5raWR9IG5vdCBmb3VuZCBpbiB0aGUgSldLU2ApO1xuICAgICAgICB9XG4gICAgICAgIGp3ayA9IGxvY2F0ZWRKd2s7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5QYXJhbWV0ZXJWYWxpZGF0aW9uRXJyb3IoW1xuICAgICAgICAgICAgYEV4cGVjdGVkIGEgdmFsaWQgSldLIG9yIEpXS1MgKHBhcnNlZCBhcyBKYXZhU2NyaXB0IG9iamVjdCksIGJ1dCByZWNlaXZlZDogJHtqd2tPckp3a3N9LmAsXG4gICAgICAgICAgICBcIklmIHlvdSdyZSBwYXNzaW5nIGEgSldLUyBVUkksIHVzZSB0aGUgYXN5bmMgdmVyaWZ5KCkgbWV0aG9kIGluc3RlYWQsIGl0IHdpbGwgZG93bmxvYWQgYW5kIHBhcnNlIHRoZSBKV0tTIGZvciB5b3VcIixcbiAgICAgICAgXS5qb2luKCkpO1xuICAgIH1cbiAgICB2ZXJpZnlTaWduYXR1cmVBZ2FpbnN0SndrKGhlYWRlciwgaGVhZGVyQjY0LCBwYXlsb2FkLCBwYXlsb2FkQjY0LCBzaWduYXR1cmVCNjQsIGp3aywgandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lcik7XG4gICAgdHJ5IHtcbiAgICAgICAgKDAsIGp3dF9qc18xLnZhbGlkYXRlSnd0RmllbGRzKShwYXlsb2FkLCBvcHRpb25zKTtcbiAgICAgICAgaWYgKG9wdGlvbnMuY3VzdG9tSnd0Q2hlY2spIHtcbiAgICAgICAgICAgIGNvbnN0IHJlcyA9IG9wdGlvbnMuY3VzdG9tSnd0Q2hlY2soeyBoZWFkZXIsIHBheWxvYWQsIGp3ayB9KTtcbiAgICAgICAgICAgICgwLCBhc3NlcnRfanNfMS5hc3NlcnRJc05vdFByb21pc2UpKHJlcywgKCkgPT4gbmV3IGVycm9yX2pzXzEuUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yKFwiQ3VzdG9tIEpXVCBjaGVja3MgbXVzdCBiZSBzeW5jaHJvbm91cyBidXQgYSBwcm9taXNlIHdhcyByZXR1cm5lZFwiKSk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgY2F0Y2ggKGVycikge1xuICAgICAgICBpZiAob3B0aW9ucy5pbmNsdWRlUmF3Snd0SW5FcnJvcnMgJiYgZXJyIGluc3RhbmNlb2YgZXJyb3JfanNfMS5Kd3RJbnZhbGlkQ2xhaW1FcnJvcikge1xuICAgICAgICAgICAgdGhyb3cgZXJyLndpdGhSYXdKd3QoZGVjb21wb3NlZEp3dCk7XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgZXJyO1xuICAgIH1cbiAgICByZXR1cm4gcGF5bG9hZDtcbn1cbi8qKlxuICogQWJzdHJhY3QgY2xhc3MgcmVwcmVzZW50aW5nIGEgdmVyaWZpZXIgZm9yIEpXVHMgc2lnbmVkIHdpdGggUlNBIChlLmcuIFJTMjU2LCBSUzM4NCwgUlM1MTIpXG4gKlxuICogQSBjbGFzcyBpcyB1c2VkLCBiZWNhdXNlIHRoZXJlIGlzIHN0YXRlOlxuICogLSBUaGUgSldLUyBpcyBmZXRjaGVkIChkb3dubG9hZGVkKSBmcm9tIHRoZSBKV0tTIFVSSSBhbmQgY2FjaGVkIGluIG1lbW9yeVxuICogLSBWZXJpZmljYXRpb24gcHJvcGVydGllcyBhdCB2ZXJpZmllciBsZXZlbCwgYXJlIHVzZWQgYXMgZGVmYXVsdCBvcHRpb25zIGZvciBpbmRpdmlkdWFsIHZlcmlmeSBjYWxsc1xuICpcbiAqIFdoZW4gaW5zdGFudGlhdGluZyB0aGlzIGNsYXNzLCByZWxldmFudCB0eXBlIHBhcmFtZXRlcnMgc2hvdWxkIGJlIHByb3ZpZGVkLCBmb3IgeW91ciBjb25jcmV0ZSBjYXNlOlxuICogQHBhcmFtIFN0aWxsVG9Qcm92aWRlIFRoZSB2ZXJpZmljYXRpb24gb3B0aW9ucyB0aGF0IHlvdSB3YW50IGNhbGxlcnMgb2YgdmVyaWZ5IHRvIHByb3ZpZGUgb24gaW5kaXZpZHVhbCB2ZXJpZnkgY2FsbHNcbiAqIEBwYXJhbSBTcGVjaWZpY1ZlcmlmeVByb3BlcnRpZXMgVGhlIHZlcmlmaWNhdGlvbiBvcHRpb25zIHRoYXQgeW91J2xsIHVzZVxuICogQHBhcmFtIElzc3VlckNvbmZpZyBUaGUgaXNzdWVyIGNvbmZpZyB0aGF0IHlvdSdsbCB1c2UgKGNvbmZpZyBvcHRpb25zIGFyZSB1c2VkIGFzIGRlZmF1bHQgdmVyaWZpY2F0aW9uIG9wdGlvbnMpXG4gKiBAcGFyYW0gTXVsdGlJc3N1ZXIgVmVyaWZ5IG11bHRpcGxlIGlzc3VlcnMgKHRydWUpIG9yIGp1c3QgYSBzaW5nbGUgb25lIChmYWxzZSlcbiAqL1xuY2xhc3MgSnd0UnNhVmVyaWZpZXJCYXNlIHtcbiAgICBjb25zdHJ1Y3Rvcih2ZXJpZnlQcm9wZXJ0aWVzLCBqd2tzQ2FjaGUgPSBuZXcgandrX2pzXzEuU2ltcGxlSndrc0NhY2hlKCkpIHtcbiAgICAgICAgdGhpcy5qd2tzQ2FjaGUgPSBqd2tzQ2FjaGU7XG4gICAgICAgIHRoaXMuaXNzdWVyc0NvbmZpZyA9IG5ldyBNYXAoKTtcbiAgICAgICAgdGhpcy5wdWJsaWNLZXlDYWNoZSA9IG5ldyBLZXlPYmplY3RDYWNoZSgpO1xuICAgICAgICBpZiAoQXJyYXkuaXNBcnJheSh2ZXJpZnlQcm9wZXJ0aWVzKSkge1xuICAgICAgICAgICAgaWYgKCF2ZXJpZnlQcm9wZXJ0aWVzLmxlbmd0aCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLlBhcmFtZXRlclZhbGlkYXRpb25FcnJvcihcIlByb3ZpZGUgYXQgbGVhc3Qgb25lIGlzc3VlciBjb25maWd1cmF0aW9uXCIpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZm9yIChjb25zdCBwcm9wIG9mIHZlcmlmeVByb3BlcnRpZXMpIHtcbiAgICAgICAgICAgICAgICBpZiAodGhpcy5pc3N1ZXJzQ29uZmlnLmhhcyhwcm9wLmlzc3VlcikpIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yKGBpc3N1ZXIgJHtwcm9wLmlzc3Vlcn0gc3VwcGxpZWQgbXVsdGlwbGUgdGltZXNgKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdGhpcy5pc3N1ZXJzQ29uZmlnLnNldChwcm9wLmlzc3VlciwgdGhpcy53aXRoSndrc1VyaShwcm9wKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB0aGlzLmlzc3VlcnNDb25maWcuc2V0KHZlcmlmeVByb3BlcnRpZXMuaXNzdWVyLCB0aGlzLndpdGhKd2tzVXJpKHZlcmlmeVByb3BlcnRpZXMpKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBnZXQgZXhwZWN0ZWRJc3N1ZXJzKCkge1xuICAgICAgICByZXR1cm4gQXJyYXkuZnJvbSh0aGlzLmlzc3VlcnNDb25maWcua2V5cygpKTtcbiAgICB9XG4gICAgZ2V0SXNzdWVyQ29uZmlnKGlzc3Vlcikge1xuICAgICAgICBpZiAoIWlzc3Vlcikge1xuICAgICAgICAgICAgaWYgKHRoaXMuaXNzdWVyc0NvbmZpZy5zaXplICE9PSAxKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuUGFyYW1ldGVyVmFsaWRhdGlvbkVycm9yKFwiaXNzdWVyIG11c3QgYmUgcHJvdmlkZWRcIik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpc3N1ZXIgPSB0aGlzLmlzc3VlcnNDb25maWcua2V5cygpLm5leHQoKS52YWx1ZTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBjb25maWcgPSB0aGlzLmlzc3VlcnNDb25maWcuZ2V0KGlzc3Vlcik7XG4gICAgICAgIGlmICghY29uZmlnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5QYXJhbWV0ZXJWYWxpZGF0aW9uRXJyb3IoYGlzc3VlciBub3QgY29uZmlndXJlZDogJHtpc3N1ZXJ9YCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGNvbmZpZztcbiAgICB9XG4gICAgLyoqXG4gICAgICogVGhpcyBtZXRob2QgbG9hZHMgYSBKV0tTIHRoYXQgeW91IHByb3ZpZGUsIGludG8gdGhlIEpXS1MgY2FjaGUsIHNvIHRoYXQgaXQgaXNcbiAgICAgKiBhdmFpbGFibGUgZm9yIEpXVCB2ZXJpZmljYXRpb24uIFVzZSB0aGlzIG1ldGhvZCB0byBzcGVlZCB1cCB0aGUgZmlyc3QgSldUIHZlcmlmaWNhdGlvblxuICAgICAqICh3aGVuIHRoZSBKV0tTIHdvdWxkIG90aGVyd2lzZSBoYXZlIHRvIGJlIGRvd25sb2FkZWQgZnJvbSB0aGUgSldLUyB1cmkpLCBvciB0byBwcm92aWRlIHRoZSBKV0tTXG4gICAgICogaW4gY2FzZSB0aGUgSnd0VmVyaWZpZXIgZG9lcyBub3QgaGF2ZSBpbnRlcm5ldCBhY2Nlc3MgdG8gZG93bmxvYWQgdGhlIEpXS1NcbiAgICAgKlxuICAgICAqIEBwYXJhbSBqd2tzVGhlIEpXS1NcbiAgICAgKiBAcGFyYW0gaXNzdWVyIFRoZSBpc3N1ZXIgZm9yIHdoaWNoIHlvdSB3YW50IHRvIGNhY2hlIHRoZSBKV0tTXG4gICAgICogIFN1cHBseSB0aGlzIGZpZWxkLCBpZiB5b3UgaW5zdGFudGlhdGVkIHRoZSBKd3RWZXJpZmllciB3aXRoIG11bHRpcGxlIGlzc3VlcnNcbiAgICAgKiBAcmV0dXJucyB2b2lkXG4gICAgICovXG4gICAgY2FjaGVKd2tzKC4uLltqd2tzLCBpc3N1ZXJdKSB7XG4gICAgICAgIGNvbnN0IGlzc3VlckNvbmZpZyA9IHRoaXMuZ2V0SXNzdWVyQ29uZmlnKGlzc3Vlcik7XG4gICAgICAgIHRoaXMuandrc0NhY2hlLmFkZEp3a3MoaXNzdWVyQ29uZmlnLmp3a3NVcmksIGp3a3MpO1xuICAgICAgICB0aGlzLnB1YmxpY0tleUNhY2hlLmNsZWFyQ2FjaGUoaXNzdWVyQ29uZmlnLmlzc3Vlcik7XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEh5ZHJhdGUgdGhlIEpXS1MgY2FjaGUgZm9yIChhbGwgb2YpIHRoZSBjb25maWd1cmVkIGlzc3VlcihzKS5cbiAgICAgKiBUaGlzIHdpbGwgZmV0Y2ggYW5kIGNhY2hlIHRoZSBsYXRlc3QgYW5kIGdyZWF0ZXN0IEpXS1MgZm9yIGNvbmNlcm5lZCBpc3N1ZXIocykuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gaXNzdWVyIFRoZSBpc3N1ZXIgdG8gZmV0Y2ggdGhlIEpXS1MgZm9yXG4gICAgICogQHJldHVybnMgdm9pZFxuICAgICAqL1xuICAgIGFzeW5jIGh5ZHJhdGUoKSB7XG4gICAgICAgIGNvbnN0IGp3a3NGZXRjaGVzID0gdGhpcy5leHBlY3RlZElzc3VlcnNcbiAgICAgICAgICAgIC5tYXAoKGlzc3VlcikgPT4gdGhpcy5nZXRJc3N1ZXJDb25maWcoaXNzdWVyKS5qd2tzVXJpKVxuICAgICAgICAgICAgLm1hcCgoandrc1VyaSkgPT4gdGhpcy5qd2tzQ2FjaGUuZ2V0Sndrcyhqd2tzVXJpKSk7XG4gICAgICAgIGF3YWl0IFByb21pc2UuYWxsKGp3a3NGZXRjaGVzKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogVmVyaWZ5IChzeW5jaHJvbm91c2x5KSBhIEpXVCB0aGF0IGlzIHNpZ25lZCB1c2luZyBSUzI1NiAvIFJTMzg0IC8gUlM1MTIuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gand0IFRoZSBKV1QsIGFzIHN0cmluZ1xuICAgICAqIEBwYXJhbSBwcm9wcyBWZXJpZmljYXRpb24gcHJvcGVydGllc1xuICAgICAqIEByZXR1cm5zIFRoZSBwYXlsb2FkIG9mIHRoZSBKV1TigJPigJNpZiB0aGUgSldUIGlzIHZhbGlkLCBvdGhlcndpc2UgYW4gZXJyb3IgaXMgdGhyb3duXG4gICAgICovXG4gICAgdmVyaWZ5U3luYyguLi5band0LCBwcm9wZXJ0aWVzXSkge1xuICAgICAgICBjb25zdCB7IGRlY29tcG9zZWRKd3QsIGp3a3NVcmksIHZlcmlmeVByb3BlcnRpZXMgfSA9IHRoaXMuZ2V0VmVyaWZ5UGFyYW1ldGVycyhqd3QsIHByb3BlcnRpZXMpO1xuICAgICAgICByZXR1cm4gdGhpcy52ZXJpZnlEZWNvbXBvc2VkSnd0U3luYyhkZWNvbXBvc2VkSnd0LCBqd2tzVXJpLCB2ZXJpZnlQcm9wZXJ0aWVzKTtcbiAgICB9XG4gICAgLyoqXG4gICAgICogVmVyaWZ5IChzeW5jaHJvbm91c2x5KSBhbiBhbHJlYWR5IGRlY29tcG9zZWQgSldULCB0aGF0IGlzIHNpZ25lZCB1c2luZyBSUzI1NiAvIFJTMzg0IC8gUlM1MTIuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gZGVjb21wb3NlZEp3dCBUaGUgZGVjb21wb3NlZCBKd3RcbiAgICAgKiBAcGFyYW0gandrIFRoZSBKV0sgdG8gdmVyaWZ5IHRoZSBKV1RzIHNpZ25hdHVyZSB3aXRoXG4gICAgICogQHBhcmFtIHZlcmlmeVByb3BlcnRpZXMgVGhlIHByb3BlcnRpZXMgdG8gdXNlIGZvciB2ZXJpZmljYXRpb25cbiAgICAgKiBAcmV0dXJucyBUaGUgcGF5bG9hZCBvZiB0aGUgSldU4oCT4oCTaWYgdGhlIEpXVCBpcyB2YWxpZCwgb3RoZXJ3aXNlIGFuIGVycm9yIGlzIHRocm93blxuICAgICAqL1xuICAgIHZlcmlmeURlY29tcG9zZWRKd3RTeW5jKGRlY29tcG9zZWRKd3QsIGp3a3NVcmksIHZlcmlmeVByb3BlcnRpZXMpIHtcbiAgICAgICAgY29uc3QgandrID0gdGhpcy5qd2tzQ2FjaGUuZ2V0Q2FjaGVkSndrKGp3a3NVcmksIGRlY29tcG9zZWRKd3QpO1xuICAgICAgICByZXR1cm4gdmVyaWZ5RGVjb21wb3NlZEp3dFN5bmMoZGVjb21wb3NlZEp3dCwgandrLCB2ZXJpZnlQcm9wZXJ0aWVzLCB0aGlzLnB1YmxpY0tleUNhY2hlLnRyYW5zZm9ybUp3a1RvS2V5T2JqZWN0LmJpbmQodGhpcy5wdWJsaWNLZXlDYWNoZSkpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBWZXJpZnkgKGFzeW5jaHJvbm91c2x5KSBhIEpXVCB0aGF0IGlzIHNpZ25lZCB1c2luZyBSUzI1NiAvIFJTMzg0IC8gUlM1MTIuXG4gICAgICogVGhpcyBjYWxsIGlzIGFzeW5jaHJvbm91cywgYW5kIHRoZSBKV0tTIHdpbGwgYmUgZmV0Y2hlZCBmcm9tIHRoZSBKV0tTIHVyaSxcbiAgICAgKiBpbiBjYXNlIGl0IGlzIG5vdCB5ZXQgYXZhaWxhYmxlIGluIHRoZSBjYWNoZS5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBqd3QgVGhlIEpXVCwgYXMgc3RyaW5nXG4gICAgICogQHBhcmFtIHByb3BzIFZlcmlmaWNhdGlvbiBwcm9wZXJ0aWVzXG4gICAgICogQHJldHVybnMgUHJvbWlzZSB0aGF0IHJlc29sdmVzIHRvIHRoZSBwYXlsb2FkIG9mIHRoZSBKV1TigJPigJNpZiB0aGUgSldUIGlzIHZhbGlkLCBvdGhlcndpc2UgdGhlIHByb21pc2UgcmVqZWN0c1xuICAgICAqL1xuICAgIGFzeW5jIHZlcmlmeSguLi5band0LCBwcm9wZXJ0aWVzXSkge1xuICAgICAgICBjb25zdCB7IGRlY29tcG9zZWRKd3QsIGp3a3NVcmksIHZlcmlmeVByb3BlcnRpZXMgfSA9IHRoaXMuZ2V0VmVyaWZ5UGFyYW1ldGVycyhqd3QsIHByb3BlcnRpZXMpO1xuICAgICAgICByZXR1cm4gdGhpcy52ZXJpZnlEZWNvbXBvc2VkSnd0KGRlY29tcG9zZWRKd3QsIGp3a3NVcmksIHZlcmlmeVByb3BlcnRpZXMpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBWZXJpZnkgKGFzeW5jaHJvbm91c2x5KSBhbiBhbHJlYWR5IGRlY29tcG9zZWQgSldULCB0aGF0IGlzIHNpZ25lZCB1c2luZyBSUzI1NiAvIFJTMzg0IC8gUlM1MTIuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gZGVjb21wb3NlZEp3dCBUaGUgZGVjb21wb3NlZCBKd3RcbiAgICAgKiBAcGFyYW0gandrIFRoZSBKV0sgdG8gdmVyaWZ5IHRoZSBKV1RzIHNpZ25hdHVyZSB3aXRoXG4gICAgICogQHBhcmFtIHZlcmlmeVByb3BlcnRpZXMgVGhlIHByb3BlcnRpZXMgdG8gdXNlIGZvciB2ZXJpZmljYXRpb25cbiAgICAgKiBAcmV0dXJucyBUaGUgcGF5bG9hZCBvZiB0aGUgSldU4oCT4oCTaWYgdGhlIEpXVCBpcyB2YWxpZCwgb3RoZXJ3aXNlIGFuIGVycm9yIGlzIHRocm93blxuICAgICAqL1xuICAgIHZlcmlmeURlY29tcG9zZWRKd3QoZGVjb21wb3NlZEp3dCwgandrc1VyaSwgdmVyaWZ5UHJvcGVydGllcykge1xuICAgICAgICByZXR1cm4gdmVyaWZ5RGVjb21wb3NlZEp3dChkZWNvbXBvc2VkSnd0LCBqd2tzVXJpLCB2ZXJpZnlQcm9wZXJ0aWVzLCB0aGlzLmp3a3NDYWNoZS5nZXRKd2suYmluZCh0aGlzLmp3a3NDYWNoZSksIHRoaXMucHVibGljS2V5Q2FjaGUudHJhbnNmb3JtSndrVG9LZXlPYmplY3QuYmluZCh0aGlzLnB1YmxpY0tleUNhY2hlKSk7XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEdldCB0aGUgdmVyaWZpY2F0aW9uIHBhcmFtZXRlcnMgdG8gdXNlLCBieSBtZXJnaW5nIHRoZSBpc3N1ZXIgY29uZmlndXJhdGlvbixcbiAgICAgKiB3aXRoIHRoZSBvdmVycmlkaW5nIHByb3BlcnRpZXMgdGhhdCBhcmUgbm93IHByb3ZpZGVkXG4gICAgICpcbiAgICAgKiBAcGFyYW0gand0OiB0aGUgSldUIHRoYXQgaXMgZ29pbmcgdG8gYmUgdmVyaWZpZWRcbiAgICAgKiBAcGFyYW0gdmVyaWZ5UHJvcGVydGllczogdGhlIG92ZXJyaWRpbmcgcHJvcGVydGllcywgdGhhdCBvdmVycmlkZSB0aGUgaXNzdWVyIGNvbmZpZ3VyYXRpb25cbiAgICAgKiBAcmV0dXJucyBUaGUgbWVyZ2VkIHZlcmlmaWNhdGlvbiBwYXJhbWV0ZXJzXG4gICAgICovXG4gICAgZ2V0VmVyaWZ5UGFyYW1ldGVycyhqd3QsIHZlcmlmeVByb3BlcnRpZXMpIHtcbiAgICAgICAgY29uc3QgZGVjb21wb3NlZEp3dCA9ICgwLCBqd3RfanNfMS5kZWNvbXBvc2VKd3QpKGp3dCk7XG4gICAgICAgICgwLCBhc3NlcnRfanNfMS5hc3NlcnRTdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKShcIklzc3VlclwiLCBkZWNvbXBvc2VkSnd0LnBheWxvYWQuaXNzLCB0aGlzLmV4cGVjdGVkSXNzdWVycywgZXJyb3JfanNfMS5Kd3RJbnZhbGlkSXNzdWVyRXJyb3IpO1xuICAgICAgICBjb25zdCBpc3N1ZXJDb25maWcgPSB0aGlzLmdldElzc3VlckNvbmZpZyhkZWNvbXBvc2VkSnd0LnBheWxvYWQuaXNzKTtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIGRlY29tcG9zZWRKd3QsXG4gICAgICAgICAgICBqd2tzVXJpOiBpc3N1ZXJDb25maWcuandrc1VyaSxcbiAgICAgICAgICAgIHZlcmlmeVByb3BlcnRpZXM6IHtcbiAgICAgICAgICAgICAgICAuLi5pc3N1ZXJDb25maWcsXG4gICAgICAgICAgICAgICAgLi4udmVyaWZ5UHJvcGVydGllcyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgIH07XG4gICAgfVxuICAgIC8qKlxuICAgICAqIEdldCBpc3N1ZXIgY29uZmlnIHdpdGggSldLUyBVUkksIGJ5IGFkZGluZyBhIGRlZmF1bHQgSldLUyBVUkkgaWYgbmVlZGVkXG4gICAgICpcbiAgICAgKiBAcGFyYW0gY29uZmlnOiB0aGUgaXNzdWVyIGNvbmZpZy5cbiAgICAgKiBAcmV0dXJucyBUaGUgY29uZmlnIHdpdGggSldLUyBVUklcbiAgICAgKi9cbiAgICB3aXRoSndrc1VyaShjb25maWcpIHtcbiAgICAgICAgaWYgKGNvbmZpZy5qd2tzVXJpKSB7XG4gICAgICAgICAgICByZXR1cm4gY29uZmlnO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGlzc3VlclVyaSA9IG5ldyB1cmxfMS5VUkwoY29uZmlnLmlzc3Vlcik7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBqd2tzVXJpOiBuZXcgdXJsXzEuVVJMKCgwLCBwYXRoXzEuam9pbikoaXNzdWVyVXJpLnBhdGhuYW1lLCBcIi8ud2VsbC1rbm93bi9qd2tzLmpzb25cIiksIGNvbmZpZy5pc3N1ZXIpLmhyZWYsXG4gICAgICAgICAgICAuLi5jb25maWcsXG4gICAgICAgIH07XG4gICAgfVxufVxuZXhwb3J0cy5Kd3RSc2FWZXJpZmllckJhc2UgPSBKd3RSc2FWZXJpZmllckJhc2U7XG4vKipcbiAqIENsYXNzIHJlcHJlc2VudGluZyBhIHZlcmlmaWVyIGZvciBKV1RzIHNpZ25lZCB3aXRoIFJTQSAoZS5nLiBSUzI1NiAvIFJTMzg0IC8gUlM1MTIpXG4gKi9cbmNsYXNzIEp3dFJzYVZlcmlmaWVyIGV4dGVuZHMgSnd0UnNhVmVyaWZpZXJCYXNlIHtcbiAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgQHR5cGVzY3JpcHQtZXNsaW50L2V4cGxpY2l0LW1vZHVsZS1ib3VuZGFyeS10eXBlc1xuICAgIHN0YXRpYyBjcmVhdGUodmVyaWZ5UHJvcGVydGllcywgYWRkaXRpb25hbFByb3BlcnRpZXMpIHtcbiAgICAgICAgcmV0dXJuIG5ldyB0aGlzKHZlcmlmeVByb3BlcnRpZXMsIGFkZGl0aW9uYWxQcm9wZXJ0aWVzPy5qd2tzQ2FjaGUpO1xuICAgIH1cbn1cbmV4cG9ydHMuSnd0UnNhVmVyaWZpZXIgPSBKd3RSc2FWZXJpZmllcjtcbi8qKlxuICogVHJhbnNmb3JtIHRoZSBKV0sgaW50byBhbiBSU0EgcHVibGljIGtleSBpbiBOb2RlLmpzIG5hdGl2ZSBrZXkgb2JqZWN0IGZvcm1hdFxuICpcbiAqIEBwYXJhbSBqd2s6IHRoZSBKV0tcbiAqIEByZXR1cm5zIHRoZSBSU0EgcHVibGljIGtleSBpbiBOb2RlLmpzIG5hdGl2ZSBrZXkgb2JqZWN0IGZvcm1hdFxuICovXG5jb25zdCB0cmFuc2Zvcm1Kd2tUb0tleU9iamVjdCA9IChqd2spID0+ICgwLCBjcnlwdG9fMS5jcmVhdGVQdWJsaWNLZXkpKHtcbiAgICBrZXk6ICgwLCBhc24xX2pzXzEuY29uc3RydWN0UHVibGljS2V5SW5EZXJGb3JtYXQpKEJ1ZmZlci5mcm9tKGp3ay5uLCBcImJhc2U2NFwiKSwgQnVmZmVyLmZyb20oandrLmUsIFwiYmFzZTY0XCIpKSxcbiAgICBmb3JtYXQ6IFwiZGVyXCIsXG4gICAgdHlwZTogXCJzcGtpXCIsXG59KTtcbmV4cG9ydHMudHJhbnNmb3JtSndrVG9LZXlPYmplY3QgPSB0cmFuc2Zvcm1Kd2tUb0tleU9iamVjdDtcbi8qKlxuICogQ2xhc3MgcmVwcmVzZW50aW5nIGEgY2FjaGUgb2YgUlNBIHB1YmxpYyBrZXlzIGluIE5vZGUuanMgbmF0aXZlIGtleSBvYmplY3QgZm9ybWF0XG4gKlxuICogQmVjYXVzZSBpdCB0YWtlcyBhIGJpdCBvZiBjb21wdXRlIHRpbWUgdG8gdHVybiBhIEpXSyBpbnRvIE5vZGUuanMgbmF0aXZlIGtleSBvYmplY3QgZm9ybWF0LFxuICogd2Ugd2FudCB0byBjYWNoZSB0aGlzIGNvbXB1dGF0aW9uLlxuICovXG5jbGFzcyBLZXlPYmplY3RDYWNoZSB7XG4gICAgY29uc3RydWN0b3IoandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lciA9IGV4cG9ydHMudHJhbnNmb3JtSndrVG9LZXlPYmplY3QpIHtcbiAgICAgICAgdGhpcy5qd2tUb0tleU9iamVjdFRyYW5zZm9ybWVyID0gandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lcjtcbiAgICAgICAgdGhpcy5wdWJsaWNLZXlzID0gbmV3IE1hcCgpO1xuICAgIH1cbiAgICAvKipcbiAgICAgKiBUcmFuc2Zvcm0gdGhlIEpXSyBpbnRvIGFuIFJTQSBwdWJsaWMga2V5IGluIE5vZGUuanMgbmF0aXZlIGtleSBvYmplY3QgZm9ybWF0LlxuICAgICAqIElmIHRoZSB0cmFuc2Zvcm1lZCBKV0sgaXMgYWxyZWFkeSBpbiB0aGUgY2FjaGUsIGl0IGlzIHJldHVybmVkIGZyb20gdGhlIGNhY2hlIGluc3RlYWQuXG4gICAgICogVGhlIGNhY2hlIGtleXMgYXJlOiBpc3N1ZXIsIEpXSyBraWQgKGtleSBpZClcbiAgICAgKlxuICAgICAqIEBwYXJhbSBqd2s6IHRoZSBKV0tcbiAgICAgKiBAcGFyYW0gaXNzdWVyOiB0aGUgaXNzdWVyIHRoYXQgdXNlcyB0aGUgSldLIGZvciBzaWduaW5nIEpXVHNcbiAgICAgKiBAcmV0dXJucyB0aGUgUlNBIHB1YmxpYyBrZXkgaW4gTm9kZS5qcyBuYXRpdmUga2V5IG9iamVjdCBmb3JtYXRcbiAgICAgKi9cbiAgICB0cmFuc2Zvcm1Kd2tUb0tleU9iamVjdChqd2ssIGlzc3Vlcikge1xuICAgICAgICBpZiAoIWlzc3Vlcikge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lcihqd2spO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGNhY2hlZFB1YmxpY0tleSA9IHRoaXMucHVibGljS2V5cy5nZXQoaXNzdWVyKT8uZ2V0KGp3ay5raWQpO1xuICAgICAgICBpZiAoY2FjaGVkUHVibGljS2V5KSB7XG4gICAgICAgICAgICByZXR1cm4gY2FjaGVkUHVibGljS2V5O1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHB1YmxpY0tleSA9IHRoaXMuandrVG9LZXlPYmplY3RUcmFuc2Zvcm1lcihqd2spO1xuICAgICAgICBjb25zdCBjYWNoZWRJc3N1ZXIgPSB0aGlzLnB1YmxpY0tleXMuZ2V0KGlzc3Vlcik7XG4gICAgICAgIGlmIChjYWNoZWRJc3N1ZXIpIHtcbiAgICAgICAgICAgIGNhY2hlZElzc3Vlci5zZXQoandrLmtpZCwgcHVibGljS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMucHVibGljS2V5cy5zZXQoaXNzdWVyLCBuZXcgTWFwKFtbandrLmtpZCwgcHVibGljS2V5XV0pKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcHVibGljS2V5O1xuICAgIH1cbiAgICBjbGVhckNhY2hlKGlzc3Vlcikge1xuICAgICAgICB0aGlzLnB1YmxpY0tleXMuZGVsZXRlKGlzc3Vlcik7XG4gICAgfVxufVxuZXhwb3J0cy5LZXlPYmplY3RDYWNoZSA9IEtleU9iamVjdENhY2hlO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgQW1hem9uLmNvbSwgSW5jLiBvciBpdHMgYWZmaWxpYXRlcy4gQWxsIFJpZ2h0cyBSZXNlcnZlZC5cbi8vIFNQRFgtTGljZW5zZS1JZGVudGlmaWVyOiBBcGFjaGUtMi4wXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG5leHBvcnRzLnZhbGlkYXRlSnd0RmllbGRzID0gZXhwb3J0cy5kZWNvbXBvc2VKd3QgPSB2b2lkIDA7XG5jb25zdCBhc3NlcnRfanNfMSA9IHJlcXVpcmUoXCIuL2Fzc2VydC5qc1wiKTtcbmNvbnN0IHNhZmVfanNvbl9wYXJzZV9qc18xID0gcmVxdWlyZShcIi4vc2FmZS1qc29uLXBhcnNlLmpzXCIpO1xuY29uc3QgZXJyb3JfanNfMSA9IHJlcXVpcmUoXCIuL2Vycm9yLmpzXCIpO1xuLyoqXG4gKiBBc3NlcnQgdGhhdCB0aGUgYXJndW1lbnQgaXMgYSB2YWxpZCBKV1QgaGVhZGVyIG9iamVjdC5cbiAqIFRocm93cyBhbiBlcnJvciBpbiBjYXNlIGl0IGlzIG5vdC5cbiAqXG4gKiBAcGFyYW0gaGVhZGVyXG4gKiBAcmV0dXJucyB2b2lkXG4gKi9cbmZ1bmN0aW9uIGFzc2VydEp3dEhlYWRlcihoZWFkZXIpIHtcbiAgICBpZiAoISgwLCBzYWZlX2pzb25fcGFyc2VfanNfMS5pc0pzb25PYmplY3QpKGhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSnd0UGFyc2VFcnJvcihcIkpXVCBoZWFkZXIgaXMgbm90IGFuIG9iamVjdFwiKTtcbiAgICB9XG4gICAgaWYgKGhlYWRlci5hbGcgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgaGVhZGVyLmFsZyAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3RQYXJzZUVycm9yKFwiSldUIGhlYWRlciBhbGcgY2xhaW0gaXMgbm90IGEgc3RyaW5nXCIpO1xuICAgIH1cbiAgICBpZiAoaGVhZGVyLmtpZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBoZWFkZXIua2lkICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFBhcnNlRXJyb3IoXCJKV1QgaGVhZGVyIGtpZCBjbGFpbSBpcyBub3QgYSBzdHJpbmdcIik7XG4gICAgfVxufVxuLyoqXG4gKiBBc3NlcnQgdGhhdCB0aGUgYXJndW1lbnQgaXMgYSB2YWxpZCBKV1QgcGF5bG9hZCBvYmplY3QuXG4gKiBUaHJvd3MgYW4gZXJyb3IgaW4gY2FzZSBpdCBpcyBub3QuXG4gKlxuICogQHBhcmFtIHBheWxvYWRcbiAqIEByZXR1cm5zIHZvaWRcbiAqL1xuZnVuY3Rpb24gYXNzZXJ0Snd0UGF5bG9hZChwYXlsb2FkKSB7XG4gICAgaWYgKCEoMCwgc2FmZV9qc29uX3BhcnNlX2pzXzEuaXNKc29uT2JqZWN0KShwYXlsb2FkKSkge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3RQYXJzZUVycm9yKFwiSldUIHBheWxvYWQgaXMgbm90IGFuIG9iamVjdFwiKTtcbiAgICB9XG4gICAgaWYgKHBheWxvYWQuZXhwICE9PSB1bmRlZmluZWQgJiYgIU51bWJlci5pc0Zpbml0ZShwYXlsb2FkLmV4cCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSnd0UGFyc2VFcnJvcihcIkpXVCBwYXlsb2FkIGV4cCBjbGFpbSBpcyBub3QgYSBudW1iZXJcIik7XG4gICAgfVxuICAgIGlmIChwYXlsb2FkLmlzcyAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBwYXlsb2FkLmlzcyAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3RQYXJzZUVycm9yKFwiSldUIHBheWxvYWQgaXNzIGNsYWltIGlzIG5vdCBhIHN0cmluZ1wiKTtcbiAgICB9XG4gICAgaWYgKHBheWxvYWQuYXVkICE9PSB1bmRlZmluZWQgJiZcbiAgICAgICAgdHlwZW9mIHBheWxvYWQuYXVkICE9PSBcInN0cmluZ1wiICYmXG4gICAgICAgICghQXJyYXkuaXNBcnJheShwYXlsb2FkLmF1ZCkgfHxcbiAgICAgICAgICAgIHBheWxvYWQuYXVkLnNvbWUoKGF1ZCkgPT4gdHlwZW9mIGF1ZCAhPT0gXCJzdHJpbmdcIikpKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFBhcnNlRXJyb3IoXCJKV1QgcGF5bG9hZCBhdWQgY2xhaW0gaXMgbm90IGEgc3RyaW5nIG9yIGFycmF5IG9mIHN0cmluZ3NcIik7XG4gICAgfVxuICAgIGlmIChwYXlsb2FkLm5iZiAhPT0gdW5kZWZpbmVkICYmICFOdW1iZXIuaXNGaW5pdGUocGF5bG9hZC5uYmYpKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFBhcnNlRXJyb3IoXCJKV1QgcGF5bG9hZCBuYmYgY2xhaW0gaXMgbm90IGEgbnVtYmVyXCIpO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5pYXQgIT09IHVuZGVmaW5lZCAmJiAhTnVtYmVyLmlzRmluaXRlKHBheWxvYWQuaWF0KSkge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3RQYXJzZUVycm9yKFwiSldUIHBheWxvYWQgaWF0IGNsYWltIGlzIG5vdCBhIG51bWJlclwiKTtcbiAgICB9XG4gICAgaWYgKHBheWxvYWQuc2NvcGUgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgcGF5bG9hZC5zY29wZSAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3RQYXJzZUVycm9yKFwiSldUIHBheWxvYWQgc2NvcGUgY2xhaW0gaXMgbm90IGEgc3RyaW5nXCIpO1xuICAgIH1cbiAgICBpZiAocGF5bG9hZC5qdGkgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgcGF5bG9hZC5qdGkgIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgdGhyb3cgbmV3IGVycm9yX2pzXzEuSnd0UGFyc2VFcnJvcihcIkpXVCBwYXlsb2FkIGp0aSBjbGFpbSBpcyBub3QgYSBzdHJpbmdcIik7XG4gICAgfVxufVxuLyoqXG4gKiBTYW5pdHkgY2hlY2ssIGRlY29tcG9zZSBhbmQgSlNPTiBwYXJzZSBhIEpXVCBzdHJpbmcgaW50byBpdHMgY29uc3RpdHVlbnQgcGFydHM6XG4gKiAtIGhlYWRlciBvYmplY3RcbiAqIC0gcGF5bG9hZCBvYmplY3RcbiAqIC0gc2lnbmF0dXJlIHN0cmluZ1xuICpcbiAqIEBwYXJhbSBqd3QgVGhlIEpXVCAoYXMgc3RyaW5nKVxuICogQHJldHVybnMgdGhlIGRlY29tcG9zZWQgSldUXG4gKi9cbmZ1bmN0aW9uIGRlY29tcG9zZUp3dChqd3QpIHtcbiAgICAvLyBTYW5pdHkgY2hlY2tzIG9uIEpXVFxuICAgIGlmICghand0KSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFBhcnNlRXJyb3IoXCJFbXB0eSBKV1RcIik7XG4gICAgfVxuICAgIGlmICh0eXBlb2Ygand0ICE9PSBcInN0cmluZ1wiKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFBhcnNlRXJyb3IoXCJKV1QgaXMgbm90IGEgc3RyaW5nXCIpO1xuICAgIH1cbiAgICBpZiAoIWp3dC5tYXRjaCgvXltBLVphLXowLTlfLV0rXFwuW0EtWmEtejAtOV8tXStcXC5bQS1aYS16MC05Xy1dKyQvKSkge1xuICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3RQYXJzZUVycm9yKFwiSldUIHN0cmluZyBkb2VzIG5vdCBjb25zaXN0IG9mIGV4YWN0bHkgMyBwYXJ0cyAoaGVhZGVyLCBwYXlsb2FkLCBzaWduYXR1cmUpXCIpO1xuICAgIH1cbiAgICBjb25zdCBbaGVhZGVyQjY0LCBwYXlsb2FkQjY0LCBzaWduYXR1cmVCNjRdID0gand0LnNwbGl0KFwiLlwiKTtcbiAgICAvLyBCNjQgZGVjb2RlIGhlYWRlciBhbmQgcGF5bG9hZFxuICAgIGNvbnN0IFtoZWFkZXJTdHJpbmcsIHBheWxvYWRTdHJpbmddID0gW2hlYWRlckI2NCwgcGF5bG9hZEI2NF0ubWFwKChiNjQpID0+IEJ1ZmZlci5mcm9tKGI2NCwgXCJiYXNlNjRcIikudG9TdHJpbmcoXCJ1dGY4XCIpKTtcbiAgICAvLyBQYXJzZSBoZWFkZXJcbiAgICBsZXQgaGVhZGVyO1xuICAgIHRyeSB7XG4gICAgICAgIGhlYWRlciA9ICgwLCBzYWZlX2pzb25fcGFyc2VfanNfMS5zYWZlSnNvblBhcnNlKShoZWFkZXJTdHJpbmcpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFBhcnNlRXJyb3IoXCJJbnZhbGlkIEpXVC4gSGVhZGVyIGlzIG5vdCBhIHZhbGlkIEpTT04gb2JqZWN0XCIsIGVycik7XG4gICAgfVxuICAgIGFzc2VydEp3dEhlYWRlcihoZWFkZXIpO1xuICAgIC8vIHBhcnNlIHBheWxvYWRcbiAgICBsZXQgcGF5bG9hZDtcbiAgICB0cnkge1xuICAgICAgICBwYXlsb2FkID0gKDAsIHNhZmVfanNvbl9wYXJzZV9qc18xLnNhZmVKc29uUGFyc2UpKHBheWxvYWRTdHJpbmcpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dFBhcnNlRXJyb3IoXCJJbnZhbGlkIEpXVC4gUGF5bG9hZCBpcyBub3QgYSB2YWxpZCBKU09OIG9iamVjdFwiLCBlcnIpO1xuICAgIH1cbiAgICBhc3NlcnRKd3RQYXlsb2FkKHBheWxvYWQpO1xuICAgIHJldHVybiB7XG4gICAgICAgIGhlYWRlcixcbiAgICAgICAgaGVhZGVyQjY0LFxuICAgICAgICBwYXlsb2FkLFxuICAgICAgICBwYXlsb2FkQjY0LFxuICAgICAgICBzaWduYXR1cmVCNjQsXG4gICAgfTtcbn1cbmV4cG9ydHMuZGVjb21wb3NlSnd0ID0gZGVjb21wb3NlSnd0O1xuLyoqXG4gKiBWYWxpZGF0ZSBKV1QgcGF5bG9hZCBmaWVsZHMuIFRocm93cyBhbiBlcnJvciBpbiBjYXNlIHRoZXJlJ3MgYW55IHZhbGlkYXRpb24gaXNzdWUuXG4gKlxuICogQHBhcmFtIHBheWxvYWQgVGhlIChKU09OIHBhcnNlZCkgSldUIHBheWxvYWRcbiAqIEBwYXJhbSBvcHRpb25zIFRoZSBvcHRpb25zIHRvIHVzZSBkdXJpbmcgdmFsaWRhdGlvblxuICogQHJldHVybnMgdm9pZFxuICovXG5mdW5jdGlvbiB2YWxpZGF0ZUp3dEZpZWxkcyhwYXlsb2FkLCBvcHRpb25zKSB7XG4gICAgLy8gQ2hlY2sgZXhwaXJ5XG4gICAgaWYgKHBheWxvYWQuZXhwICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgaWYgKHBheWxvYWQuZXhwICsgKG9wdGlvbnMuZ3JhY2VTZWNvbmRzID8/IDApIDwgRGF0ZS5ub3coKSAvIDEwMDApIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLkp3dEV4cGlyZWRFcnJvcihgVG9rZW4gZXhwaXJlZCBhdCAke25ldyBEYXRlKHBheWxvYWQuZXhwICogMTAwMCkudG9JU09TdHJpbmcoKX1gLCBwYXlsb2FkLmV4cCk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgLy8gQ2hlY2sgbm90IGJlZm9yZVxuICAgIGlmIChwYXlsb2FkLm5iZiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGlmIChwYXlsb2FkLm5iZiAtIChvcHRpb25zLmdyYWNlU2Vjb25kcyA/PyAwKSA+IERhdGUubm93KCkgLyAxMDAwKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JfanNfMS5Kd3ROb3RCZWZvcmVFcnJvcihgVG9rZW4gY2FuJ3QgYmUgdXNlZCBiZWZvcmUgJHtuZXcgRGF0ZShwYXlsb2FkLm5iZiAqIDEwMDApLnRvSVNPU3RyaW5nKCl9YCwgcGF5bG9hZC5uYmYpO1xuICAgICAgICB9XG4gICAgfVxuICAgIC8vIENoZWNrIEpXVCBpc3N1ZXJcbiAgICBpZiAob3B0aW9ucy5pc3N1ZXIgIT09IG51bGwpIHtcbiAgICAgICAgaWYgKG9wdGlvbnMuaXNzdWVyID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLlBhcmFtZXRlclZhbGlkYXRpb25FcnJvcihcImlzc3VlciBtdXN0IGJlIHByb3ZpZGVkIG9yIHNldCB0byBudWxsIGV4cGxpY2l0bHlcIik7XG4gICAgICAgIH1cbiAgICAgICAgKDAsIGFzc2VydF9qc18xLmFzc2VydFN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcpKFwiSXNzdWVyXCIsIHBheWxvYWQuaXNzLCBvcHRpb25zLmlzc3VlciwgZXJyb3JfanNfMS5Kd3RJbnZhbGlkSXNzdWVyRXJyb3IpO1xuICAgIH1cbiAgICAvLyBDaGVjayBhdWRpZW5jZVxuICAgIGlmIChvcHRpb25zLmF1ZGllbmNlICE9PSBudWxsKSB7XG4gICAgICAgIGlmIChvcHRpb25zLmF1ZGllbmNlID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcl9qc18xLlBhcmFtZXRlclZhbGlkYXRpb25FcnJvcihcImF1ZGllbmNlIG11c3QgYmUgcHJvdmlkZWQgb3Igc2V0IHRvIG51bGwgZXhwbGljaXRseVwiKTtcbiAgICAgICAgfVxuICAgICAgICAoMCwgYXNzZXJ0X2pzXzEuYXNzZXJ0U3RyaW5nQXJyYXlzT3ZlcmxhcCkoXCJBdWRpZW5jZVwiLCBwYXlsb2FkLmF1ZCwgb3B0aW9ucy5hdWRpZW5jZSwgZXJyb3JfanNfMS5Kd3RJbnZhbGlkQXVkaWVuY2VFcnJvcik7XG4gICAgfVxuICAgIC8vIENoZWNrIHNjb3BlXG4gICAgaWYgKG9wdGlvbnMuc2NvcGUgIT0gbnVsbCkge1xuICAgICAgICAoMCwgYXNzZXJ0X2pzXzEuYXNzZXJ0U3RyaW5nQXJyYXlzT3ZlcmxhcCkoXCJTY29wZVwiLCBwYXlsb2FkLnNjb3BlPy5zcGxpdChcIiBcIiksIG9wdGlvbnMuc2NvcGUsIGVycm9yX2pzXzEuSnd0SW52YWxpZFNjb3BlRXJyb3IpO1xuICAgIH1cbn1cbmV4cG9ydHMudmFsaWRhdGVKd3RGaWVsZHMgPSB2YWxpZGF0ZUp3dEZpZWxkcztcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IEFtYXpvbi5jb20sIEluYy4gb3IgaXRzIGFmZmlsaWF0ZXMuIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4vLyBTUERYLUxpY2Vuc2UtSWRlbnRpZmllcjogQXBhY2hlLTIuMFxuLy9cbi8vIFV0aWxpdHkgdG8gcGFyc2UgSlNPTiBzYWZlbHlcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbmV4cG9ydHMuc2FmZUpzb25QYXJzZSA9IGV4cG9ydHMuaXNKc29uT2JqZWN0ID0gdm9pZCAwO1xuLyoqXG4gKiBDaGVjayBpZiBhIHBpZWNlIG9mIEpTT04gaXMgYSBKU09OIG9iamVjdCwgYW5kIG5vdCBlLmcuIGEgbWVyZSBzdHJpbmcgb3IgbnVsbFxuICpcbiAqIEBwYXJhbSBqIC0gdGhlIEpTT05cbiAqL1xuZnVuY3Rpb24gaXNKc29uT2JqZWN0KGopIHtcbiAgICAvLyBJdCBpcyBub3QgZW5vdWdoIHRvIGNoZWNrIHRoYXQgYHR5cGVvZiBqID09PSBcIm9iamVjdFwiYFxuICAgIC8vIGJlY2F1c2UgaW4gSlMgYHR5cGVvZiBudWxsYCBpcyBhbHNvIFwib2JqZWN0XCIsIGFuZCBzbyBpcyBgdHlwZW9mIFtdYC5cbiAgICAvLyBTbyB3ZSBuZWVkIHRvIGNoZWNrIHRoYXQgaiBpcyBhbiBvYmplY3QsIGFuZCBub3QgbnVsbCwgYW5kIG5vdCBhbiBhcnJheVxuICAgIHJldHVybiB0eXBlb2YgaiA9PT0gXCJvYmplY3RcIiAmJiAhQXJyYXkuaXNBcnJheShqKSAmJiBqICE9PSBudWxsO1xufVxuZXhwb3J0cy5pc0pzb25PYmplY3QgPSBpc0pzb25PYmplY3Q7XG4vKipcbiAqIFBhcnNlIGEgc3RyaW5nIGFzIEpTT04sIHdoaWxlIHJlbW92aW5nIF9fcHJvdG9fXyBhbmQgY29uc3RydWN0b3IsIHNvIEpTIHByb3RvdHlwZSBwb2xsdXRpb24gaXMgcHJldmVudGVkXG4gKlxuICogQHBhcmFtIHMgLSB0aGUgc3RyaW5nIHRvIEpTT04gcGFyc2VcbiAqL1xuZnVuY3Rpb24gc2FmZUpzb25QYXJzZShzKSB7XG4gICAgcmV0dXJuIEpTT04ucGFyc2UocywgKF8sIHZhbHVlKSA9PiB7XG4gICAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09IFwib2JqZWN0XCIgJiYgIUFycmF5LmlzQXJyYXkodmFsdWUpICYmIHZhbHVlICE9PSBudWxsKSB7XG4gICAgICAgICAgICBkZWxldGUgdmFsdWUuX19wcm90b19fO1xuICAgICAgICAgICAgZGVsZXRlIHZhbHVlLmNvbnN0cnVjdG9yO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9KTtcbn1cbmV4cG9ydHMuc2FmZUpzb25QYXJzZSA9IHNhZmVKc29uUGFyc2U7XG4iLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiIiwiLy8gc3RhcnR1cFxuLy8gTG9hZCBlbnRyeSBtb2R1bGUgYW5kIHJldHVybiBleHBvcnRzXG4vLyBUaGlzIGVudHJ5IG1vZHVsZSBpcyByZWZlcmVuY2VkIGJ5IG90aGVyIG1vZHVsZXMgc28gaXQgY2FuJ3QgYmUgaW5saW5lZFxudmFyIF9fd2VicGFja19leHBvcnRzX18gPSBfX3dlYnBhY2tfcmVxdWlyZV9fKFwiLi9kZXBsb3kvbGFtYmRhL2VkZ2UvaW5kZXgudHNcIik7XG4iLCIiXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=