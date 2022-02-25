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

/***/ "./deploy/edge/auth/index.ts":
/*!***********************************!*\
  !*** ./deploy/edge/auth/index.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handler = void 0;
const lambda_powertools_logger_1 = __importDefault(__webpack_require__(/*! @dazn/lambda-powertools-logger */ "./node_modules/@dazn/lambda-powertools-logger/index.js"));
const handler = async (event, context, callback) => {
    lambda_powertools_logger_1.default.info('Start Auth');
    return null;
};
exports.handler = handler;


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
/******/ 	var __webpack_exports__ = __webpack_require__("./deploy/edge/auth/index.ts");
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC9pbmRleC5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQTs7QUFFQTtBQUNBLDJCQUEyQjtBQUMzQjtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTs7QUFFQTs7Ozs7Ozs7Ozs7QUNsRUEsdUJBQXVCLG1CQUFPLENBQUMsZ0hBQXlDOztBQUV4RTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUksSUFBSTtBQUNSO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EscUJBQXFCO0FBQ3JCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSwrQ0FBK0MsK0JBQStCO0FBQzlFO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSw0RUFBNEU7QUFDNUU7QUFDQTs7QUFFQTtBQUNBLDRFQUE0RTtBQUM1RTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7QUFFQTs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDakpBLHdLQUFnRDtBQUd6QyxNQUFNLE9BQU8sR0FBNkIsS0FBSyxFQUFFLEtBQUssRUFBRSxPQUFPLEVBQUUsUUFBUSxFQUFFLEVBQUU7SUFDbEYsa0NBQUcsQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDO0lBQ3RCLE9BQU8sSUFBSTtBQUNiLENBQUM7QUFIWSxlQUFPLFdBR25COzs7Ozs7O1VDTkQ7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTs7VUFFQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTs7OztVRXRCQTtVQUNBO1VBQ0E7VUFDQSIsInNvdXJjZXMiOlsid2VicGFjazovL2NvZ25pdG8tc2FtcGxlLy4vbm9kZV9tb2R1bGVzL0BkYXpuL2xhbWJkYS1wb3dlcnRvb2xzLWNvcnJlbGF0aW9uLWlkcy9pbmRleC5qcyIsIndlYnBhY2s6Ly9jb2duaXRvLXNhbXBsZS8uL25vZGVfbW9kdWxlcy9AZGF6bi9sYW1iZGEtcG93ZXJ0b29scy1sb2dnZXIvaW5kZXguanMiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvLi9kZXBsb3kvZWRnZS9hdXRoL2luZGV4LnRzIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlL3dlYnBhY2svYmVmb3JlLXN0YXJ0dXAiLCJ3ZWJwYWNrOi8vY29nbml0by1zYW1wbGUvd2VicGFjay9zdGFydHVwIiwid2VicGFjazovL2NvZ25pdG8tc2FtcGxlL3dlYnBhY2svYWZ0ZXItc3RhcnR1cCJdLCJzb3VyY2VzQ29udGVudCI6WyJjb25zdCBERUJVR19MT0dfRU5BQkxFRCA9ICdkZWJ1Zy1sb2ctZW5hYmxlZCdcblxuY2xhc3MgQ29ycmVsYXRpb25JZHMge1xuICBjb25zdHJ1Y3RvciAoY29udGV4dCA9IHt9KSB7XG4gICAgdGhpcy5jb250ZXh0ID0gY29udGV4dFxuICB9XG5cbiAgY2xlYXJBbGwgKCkge1xuICAgIHRoaXMuY29udGV4dCA9IHt9XG4gIH1cblxuICByZXBsYWNlQWxsV2l0aCAoY3R4KSB7XG4gICAgdGhpcy5jb250ZXh0ID0gY3R4XG4gIH1cblxuICBzZXQgKGtleSwgdmFsdWUpIHtcbiAgICBpZiAoIWtleS5zdGFydHNXaXRoKCd4LWNvcnJlbGF0aW9uLScpKSB7XG4gICAgICBrZXkgPSAneC1jb3JyZWxhdGlvbi0nICsga2V5XG4gICAgfVxuXG4gICAgdGhpcy5jb250ZXh0W2tleV0gPSB2YWx1ZVxuICB9XG5cbiAgZ2V0ICgpIHtcbiAgICByZXR1cm4gdGhpcy5jb250ZXh0XG4gIH1cblxuICBnZXQgZGVidWdMb2dnaW5nRW5hYmxlZCAoKSB7XG4gICAgcmV0dXJuIHRoaXMuY29udGV4dFtERUJVR19MT0dfRU5BQkxFRF0gPT09ICd0cnVlJ1xuICB9XG5cbiAgc2V0IGRlYnVnTG9nZ2luZ0VuYWJsZWQgKGVuYWJsZWQpIHtcbiAgICB0aGlzLmNvbnRleHRbREVCVUdfTE9HX0VOQUJMRURdID0gZW5hYmxlZCA/ICd0cnVlJyA6ICdmYWxzZSdcbiAgfVxuXG4gIHN0YXRpYyBjbGVhckFsbCAoKSB7XG4gICAgZ2xvYmFsQ29ycmVsYXRpb25JZHMuY2xlYXJBbGwoKVxuICB9XG5cbiAgc3RhdGljIHJlcGxhY2VBbGxXaXRoICguLi5hcmdzKSB7XG4gICAgZ2xvYmFsQ29ycmVsYXRpb25JZHMucmVwbGFjZUFsbFdpdGgoLi4uYXJncylcbiAgfVxuXG4gIHN0YXRpYyBzZXQgKC4uLmFyZ3MpIHtcbiAgICBnbG9iYWxDb3JyZWxhdGlvbklkcy5zZXQoLi4uYXJncylcbiAgfVxuXG4gIHN0YXRpYyBnZXQgKCkge1xuICAgIHJldHVybiBnbG9iYWxDb3JyZWxhdGlvbklkcy5nZXQoKVxuICB9XG5cbiAgc3RhdGljIGdldCBkZWJ1Z0xvZ2dpbmdFbmFibGVkICgpIHtcbiAgICByZXR1cm4gZ2xvYmFsQ29ycmVsYXRpb25JZHMuZGVidWdMb2dnaW5nRW5hYmxlZFxuICB9XG5cbiAgc3RhdGljIHNldCBkZWJ1Z0xvZ2dpbmdFbmFibGVkIChlbmFibGVkKSB7XG4gICAgZ2xvYmFsQ29ycmVsYXRpb25JZHMuZGVidWdMb2dnaW5nRW5hYmxlZCA9IGVuYWJsZWRcbiAgfVxufVxuXG5pZiAoIWdsb2JhbC5DT1JSRUxBVElPTl9JRFMpIHtcbiAgZ2xvYmFsLkNPUlJFTEFUSU9OX0lEUyA9IG5ldyBDb3JyZWxhdGlvbklkcygpXG59XG5cbmNvbnN0IGdsb2JhbENvcnJlbGF0aW9uSWRzID0gZ2xvYmFsLkNPUlJFTEFUSU9OX0lEU1xuXG5tb2R1bGUuZXhwb3J0cyA9IENvcnJlbGF0aW9uSWRzXG4iLCJjb25zdCBDb3JyZWxhdGlvbklkcyA9IHJlcXVpcmUoJ0BkYXpuL2xhbWJkYS1wb3dlcnRvb2xzLWNvcnJlbGF0aW9uLWlkcycpXG5cbi8vIExldmVscyBoZXJlIGFyZSBpZGVudGljYWwgdG8gYnVueWFuIHByYWN0aWNlc1xuLy8gaHR0cHM6Ly9naXRodWIuY29tL3RyZW50bS9ub2RlLWJ1bnlhbiNsZXZlbHNcbmNvbnN0IExvZ0xldmVscyA9IHtcbiAgREVCVUc6IDIwLFxuICBJTkZPOiAzMCxcbiAgV0FSTjogNDAsXG4gIEVSUk9SOiA1MFxufVxuXG4vLyBtb3N0IG9mIHRoZXNlIGFyZSBhdmFpbGFibGUgdGhyb3VnaCB0aGUgTm9kZS5qcyBleGVjdXRpb24gZW52aXJvbm1lbnQgZm9yIExhbWJkYVxuLy8gc2VlIGh0dHBzOi8vZG9jcy5hd3MuYW1hem9uLmNvbS9sYW1iZGEvbGF0ZXN0L2RnL2N1cnJlbnQtc3VwcG9ydGVkLXZlcnNpb25zLmh0bWxcbmNvbnN0IERFRkFVTFRfQ09OVEVYVCA9IHtcbiAgYXdzUmVnaW9uOiBwcm9jZXNzLmVudi5BV1NfUkVHSU9OIHx8IHByb2Nlc3MuZW52LkFXU19ERUZBVUxUX1JFR0lPTixcbiAgZnVuY3Rpb25OYW1lOiBwcm9jZXNzLmVudi5BV1NfTEFNQkRBX0ZVTkNUSU9OX05BTUUsXG4gIGZ1bmN0aW9uVmVyc2lvbjogcHJvY2Vzcy5lbnYuQVdTX0xBTUJEQV9GVU5DVElPTl9WRVJTSU9OLFxuICBmdW5jdGlvbk1lbW9yeVNpemU6IHByb2Nlc3MuZW52LkFXU19MQU1CREFfRlVOQ1RJT05fTUVNT1JZX1NJWkUsXG4gIGVudmlyb25tZW50OiBwcm9jZXNzLmVudi5FTlZJUk9OTUVOVCB8fCBwcm9jZXNzLmVudi5TVEFHRSAvLyBjb252ZW50aW9uIGluIG91ciBmdW5jdGlvbnNcbn1cblxuY2xhc3MgTG9nZ2VyIHtcbiAgY29uc3RydWN0b3IgKHtcbiAgICBjb3JyZWxhdGlvbklkcyA9IENvcnJlbGF0aW9uSWRzLFxuICAgIGxldmVsID0gcHJvY2Vzcy5lbnYuTE9HX0xFVkVMXG4gIH0gPSB7fSkge1xuICAgIHRoaXMuY29ycmVsYXRpb25JZHMgPSBjb3JyZWxhdGlvbklkc1xuICAgIHRoaXMubGV2ZWwgPSAobGV2ZWwgfHwgJ0RFQlVHJykudG9VcHBlckNhc2UoKVxuICAgIHRoaXMub3JpZ2luYWxMZXZlbCA9IHRoaXMubGV2ZWxcblxuICAgIGlmIChjb3JyZWxhdGlvbklkcy5kZWJ1Z0VuYWJsZWQpIHtcbiAgICAgIHRoaXMuZW5hYmxlRGVidWcoKVxuICAgIH1cbiAgfVxuXG4gIGdldCBjb250ZXh0ICgpIHtcbiAgICByZXR1cm4ge1xuICAgICAgLi4uREVGQVVMVF9DT05URVhULFxuICAgICAgLi4udGhpcy5jb3JyZWxhdGlvbklkcy5nZXQoKVxuICAgIH1cbiAgfVxuXG4gIGlzRW5hYmxlZCAobGV2ZWwpIHtcbiAgICByZXR1cm4gbGV2ZWwgPj0gKExvZ0xldmVsc1t0aGlzLmxldmVsXSB8fCBMb2dMZXZlbHMuREVCVUcpXG4gIH1cblxuICBhcHBlbmRFcnJvciAocGFyYW1zLCBlcnIpIHtcbiAgICBpZiAoIWVycikge1xuICAgICAgcmV0dXJuIHBhcmFtc1xuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICAuLi5wYXJhbXMgfHwge30sXG4gICAgICBlcnJvck5hbWU6IGVyci5uYW1lLFxuICAgICAgZXJyb3JNZXNzYWdlOiBlcnIubWVzc2FnZSxcbiAgICAgIHN0YWNrVHJhY2U6IGVyci5zdGFja1xuICAgIH1cbiAgfVxuXG4gIGxvZyAobGV2ZWxOYW1lLCBtZXNzYWdlLCBwYXJhbXMpIHtcbiAgICBjb25zdCBsZXZlbCA9IExvZ0xldmVsc1tsZXZlbE5hbWVdXG4gICAgaWYgKCF0aGlzLmlzRW5hYmxlZChsZXZlbCkpIHtcbiAgICAgIHJldHVyblxuICAgIH1cblxuICAgIGNvbnN0IGxvZ01zZyA9IHtcbiAgICAgIC4uLnRoaXMuY29udGV4dCxcbiAgICAgIC4uLnBhcmFtcyxcbiAgICAgIGxldmVsLFxuICAgICAgc0xldmVsOiBsZXZlbE5hbWUsXG4gICAgICBtZXNzYWdlXG4gICAgfVxuXG4gICAgY29uc3QgY29uc29sZU1ldGhvZHMgPSB7XG4gICAgICBERUJVRzogY29uc29sZS5kZWJ1ZyxcbiAgICAgIElORk86IGNvbnNvbGUuaW5mbyxcbiAgICAgIFdBUk46IGNvbnNvbGUud2FybixcbiAgICAgIEVSUk9SOiBjb25zb2xlLmVycm9yXG4gICAgfVxuXG4gICAgLy8gcmUtb3JkZXIgbWVzc2FnZSBhbmQgcGFyYW1zIHRvIGFwcGVhciBlYXJsaWVyIGluIHRoZSBsb2cgcm93XG4gICAgY29uc29sZU1ldGhvZHNbbGV2ZWxOYW1lXShKU09OLnN0cmluZ2lmeSh7IG1lc3NhZ2UsIC4uLnBhcmFtcywgLi4ubG9nTXNnIH0sIChrZXksIHZhbHVlKSA9PiB0eXBlb2YgdmFsdWUgPT09ICdiaWdpbnQnXG4gICAgICA/IHZhbHVlLnRvU3RyaW5nKClcbiAgICAgIDogdmFsdWVcbiAgICApKVxuICB9XG5cbiAgZGVidWcgKG1zZywgcGFyYW1zKSB7XG4gICAgdGhpcy5sb2coJ0RFQlVHJywgbXNnLCBwYXJhbXMpXG4gIH1cblxuICBpbmZvIChtc2csIHBhcmFtcykge1xuICAgIHRoaXMubG9nKCdJTkZPJywgbXNnLCBwYXJhbXMpXG4gIH1cblxuICB3YXJuIChtc2csIHBhcmFtcywgZXJyKSB7XG4gICAgY29uc3QgcGFyYW1ldGVycyA9ICFlcnIgJiYgcGFyYW1zIGluc3RhbmNlb2YgRXJyb3IgPyB0aGlzLmFwcGVuZEVycm9yKHt9LCBwYXJhbXMpIDogdGhpcy5hcHBlbmRFcnJvcihwYXJhbXMsIGVycilcbiAgICB0aGlzLmxvZygnV0FSTicsIG1zZywgcGFyYW1ldGVycylcbiAgfVxuXG4gIGVycm9yIChtc2csIHBhcmFtcywgZXJyKSB7XG4gICAgY29uc3QgcGFyYW1ldGVycyA9ICFlcnIgJiYgcGFyYW1zIGluc3RhbmNlb2YgRXJyb3IgPyB0aGlzLmFwcGVuZEVycm9yKHt9LCBwYXJhbXMpIDogdGhpcy5hcHBlbmRFcnJvcihwYXJhbXMsIGVycilcbiAgICB0aGlzLmxvZygnRVJST1InLCBtc2csIHBhcmFtZXRlcnMpXG4gIH1cblxuICBlbmFibGVEZWJ1ZyAoKSB7XG4gICAgdGhpcy5sZXZlbCA9ICdERUJVRydcbiAgICByZXR1cm4gKCkgPT4gdGhpcy5yZXNldExldmVsKClcbiAgfVxuXG4gIHJlc2V0TGV2ZWwgKCkge1xuICAgIHRoaXMubGV2ZWwgPSB0aGlzLm9yaWdpbmFsTGV2ZWxcbiAgfVxuXG4gIHN0YXRpYyBkZWJ1ZyAoLi4uYXJncykge1xuICAgIGdsb2JhbExvZ2dlci5kZWJ1ZyguLi5hcmdzKVxuICB9XG5cbiAgc3RhdGljIGluZm8gKC4uLmFyZ3MpIHtcbiAgICBnbG9iYWxMb2dnZXIuaW5mbyguLi5hcmdzKVxuICB9XG5cbiAgc3RhdGljIHdhcm4gKC4uLmFyZ3MpIHtcbiAgICBnbG9iYWxMb2dnZXIud2FybiguLi5hcmdzKVxuICB9XG5cbiAgc3RhdGljIGVycm9yICguLi5hcmdzKSB7XG4gICAgZ2xvYmFsTG9nZ2VyLmVycm9yKC4uLmFyZ3MpXG4gIH1cblxuICBzdGF0aWMgZW5hYmxlRGVidWcgKCkge1xuICAgIHJldHVybiBnbG9iYWxMb2dnZXIuZW5hYmxlRGVidWcoKVxuICB9XG5cbiAgc3RhdGljIHJlc2V0TGV2ZWwgKCkge1xuICAgIGdsb2JhbExvZ2dlci5yZXNldExldmVsKClcbiAgfVxuXG4gIHN0YXRpYyBnZXQgbGV2ZWwgKCkge1xuICAgIHJldHVybiBnbG9iYWxMb2dnZXIubGV2ZWxcbiAgfVxufVxuXG5jb25zdCBnbG9iYWxMb2dnZXIgPSBuZXcgTG9nZ2VyKClcblxubW9kdWxlLmV4cG9ydHMgPSBMb2dnZXJcbiIsImltcG9ydCBMb2cgZnJvbSAnQGRhem4vbGFtYmRhLXBvd2VydG9vbHMtbG9nZ2VyJ1xuaW1wb3J0IHsgQ2xvdWRGcm9udFJlcXVlc3RIYW5kbGVyIH0gZnJvbSAnYXdzLWxhbWJkYSdcblxuZXhwb3J0IGNvbnN0IGhhbmRsZXI6IENsb3VkRnJvbnRSZXF1ZXN0SGFuZGxlciA9IGFzeW5jIChldmVudCwgY29udGV4dCwgY2FsbGJhY2spID0+IHtcbiAgTG9nLmluZm8oJ1N0YXJ0IEF1dGgnKVxuICByZXR1cm4gbnVsbFxufVxuIiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXS5jYWxsKG1vZHVsZS5leHBvcnRzLCBtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsIiIsIi8vIHN0YXJ0dXBcbi8vIExvYWQgZW50cnkgbW9kdWxlIGFuZCByZXR1cm4gZXhwb3J0c1xuLy8gVGhpcyBlbnRyeSBtb2R1bGUgaXMgcmVmZXJlbmNlZCBieSBvdGhlciBtb2R1bGVzIHNvIGl0IGNhbid0IGJlIGlubGluZWRcbnZhciBfX3dlYnBhY2tfZXhwb3J0c19fID0gX193ZWJwYWNrX3JlcXVpcmVfXyhcIi4vZGVwbG95L2VkZ2UvYXV0aC9pbmRleC50c1wiKTtcbiIsIiJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==