System.register("src/guid.generator", [], function(exports_1, context_1) {
    "use strict";
    var __moduleName = context_1 && context_1.id;
    var GuidGenerator;
    return {
        setters:[],
        execute: function() {
            GuidGenerator = (function () {
                function GuidGenerator() {
                }
                GuidGenerator.prototype.generate = function () {
                    var guidHolder = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
                    var hex = '0123456789abcdef';
                    var r = 0;
                    var guidResponse = "";
                    for (var i = 0; i < 36; i++) {
                        if (guidHolder[i] !== '-' && guidHolder[i] !== '4') {
                            // each x and y needs to be random
                            r = Math.random() * 16 | 0;
                        }
                        if (guidHolder[i] === 'x') {
                            guidResponse += hex[r];
                        }
                        else if (guidHolder[i] === 'y') {
                            // clock-seq-and-reserved first hex is filtered and remaining hex values are random
                            r &= 0x3; // bit and with 0011 to set pos 2 to zero ?0??
                            r |= 0x8; // set pos 3 to 1 as 1???
                            guidResponse += hex[r];
                        }
                        else {
                            guidResponse += guidHolder[i];
                        }
                    }
                    return guidResponse;
                };
                GuidGenerator.prototype.decimalToHex = function (number) {
                    var hex = number.toString(16);
                    while (hex.length < 2) {
                        hex = '0' + hex;
                    }
                    return hex;
                };
                return GuidGenerator;
            }());
            exports_1("GuidGenerator", GuidGenerator);
        }
    }
});
System.register("src/storage", [], function(exports_2, context_2) {
    "use strict";
    var __moduleName = context_2 && context_2.id;
    return {
        setters:[],
        execute: function() {
        }
    }
});
System.register("src/constants", [], function(exports_3, context_3) {
    "use strict";
    var __moduleName = context_3 && context_3.id;
    var Constants, RequestTypes;
    return {
        setters:[],
        execute: function() {
            exports_3("Constants", Constants = {
                ACCESS_TOKEN: 'access_token',
                EXPIRES_IN: 'expires_in',
                ID_TOKEN: 'id_token',
                ERROR_DESCRIPTION: 'error_description',
                SESSION_STATE: 'session_state',
                STORAGE: {
                    TOKEN_KEYS: 'adal.token.keys',
                    ACCESS_TOKEN_KEY: 'adal.access.token.key',
                    EXPIRATION_KEY: 'adal.expiration.key',
                    STATE_LOGIN: 'adal.state.login',
                    STATE_RENEW: 'adal.state.renew',
                    NONCE_IDTOKEN: 'adal.nonce.idtoken',
                    SESSION_STATE: 'adal.session.state',
                    USERNAME: 'adal.username',
                    IDTOKEN: 'adal.idtoken',
                    ERROR: 'adal.error',
                    ERROR_DESCRIPTION: 'adal.error.description',
                    LOGIN_REQUEST: 'adal.login.request',
                    LOGIN_ERROR: 'adal.login.error',
                    RENEW_STATUS: 'adal.token.renew.status'
                },
                RESOURCE_DELIMETER: '|',
                LOADFRAME_TIMEOUT: '6000',
                TOKEN_RENEW_STATUS_CANCELED: 'Canceled',
                TOKEN_RENEW_STATUS_COMPLETED: 'Completed',
                TOKEN_RENEW_STATUS_IN_PROGRESS: 'In Progress',
                LOGGING_LEVEL: {
                    ERROR: 0,
                    WARN: 1,
                    INFO: 2,
                    VERBOSE: 3
                },
                LEVEL_STRING_MAP: {
                    0: 'ERROR:',
                    1: 'WARNING:',
                    2: 'INFO:',
                    3: 'VERBOSE:'
                }
            });
            exports_3("RequestTypes", RequestTypes = {
                LOGIN: 'LOGIN',
                RENEW_TOKEN: 'RENEW_TOKEN',
                UNKNOWN: 'UNKNOWN'
            });
        }
    }
});
System.register("src/navigator", [], function(exports_4, context_4) {
    "use strict";
    var __moduleName = context_4 && context_4.id;
    var Navigator;
    return {
        setters:[],
        execute: function() {
            Navigator = (function () {
                function Navigator() {
                }
                Navigator.prototype.navigate = function (url) {
                    window.location.replace(url);
                };
                return Navigator;
            }());
            exports_4("Navigator", Navigator);
        }
    }
});
System.register("src/aad.url.config", [], function(exports_5, context_5) {
    "use strict";
    var __moduleName = context_5 && context_5.id;
    return {
        setters:[],
        execute: function() {
        }
    }
});
System.register("src/aad.url.builder", [], function(exports_6, context_6) {
    "use strict";
    var __moduleName = context_6 && context_6.id;
    var AadUrlBuilder;
    return {
        setters:[],
        execute: function() {
            AadUrlBuilder = (function () {
                function AadUrlBuilder(guidGenerator) {
                    this.addLibMetadata = function () {
                        // x-client-SKU
                        // x-client-Ver
                        return '&x-client-SKU=Js&x-client-Ver=' + this.libVersion;
                    };
                    this.guidGenerator = guidGenerator;
                    this.state = this.guidGenerator.generate();
                    this.clientRequestId = this.guidGenerator.generate();
                    this.responseType = 'id_token';
                    this.libVersion = '1.0.0';
                    this.redirectUri = window.location.href;
                }
                AadUrlBuilder.prototype.with = function (options) {
                    this.nonce = options.nonce;
                    this.tenant = options.tenant;
                    this.clientId = options.clientId;
                    this.responseType = options.responseType || this.responseType;
                    this.redirectUri = options.redirectUri || this.redirectUri;
                    this.state = options.state;
                    this.slice = options.slice || this.slice;
                    this.clientRequestId = options.clientRequestId || this.clientRequestId;
                    this.libVersion = options.libVersion || this.libVersion;
                    this.extraQueryParameter = options.extraQueryParameter || this.extraQueryParameter;
                    return this;
                };
                AadUrlBuilder.prototype.build = function () {
                    var urlNavigate = AadUrlBuilder.MicrosoftLoginUrl + this.tenant + '/oauth2/authorize';
                    urlNavigate = urlNavigate + this.serialize() + this.addLibMetadata();
                    urlNavigate = urlNavigate + '&nonce=' + encodeURIComponent(this.nonce);
                    return urlNavigate;
                };
                AadUrlBuilder.prototype.serialize = function () {
                    var str = [];
                    str.push('?response_type=' + this.responseType);
                    str.push('client_id=' + encodeURIComponent(this.clientId));
                    if (this.resource) {
                        str.push('resource=' + encodeURIComponent(this.resource));
                    }
                    str.push('redirect_uri=' + encodeURIComponent(this.redirectUri));
                    str.push('state=' + encodeURIComponent(this.state));
                    if (this.slice) {
                        str.push('slice=' + encodeURIComponent(this.slice));
                    }
                    if (this.extraQueryParameter) {
                        str.push(this.extraQueryParameter);
                    }
                    //var correlationId = this.clientRequestId ? obj.correlationId : new GuidGenerator().generate();
                    str.push('client-request-id=' + encodeURIComponent(this.clientRequestId));
                    return str.join('&');
                };
                ;
                AadUrlBuilder.MicrosoftLoginUrl = 'https://login.microsoftonline.com/';
                return AadUrlBuilder;
            }());
            exports_6("AadUrlBuilder", AadUrlBuilder);
        }
    }
});
System.register("src/user", [], function(exports_7, context_7) {
    "use strict";
    var __moduleName = context_7 && context_7.id;
    return {
        setters:[],
        execute: function() {
        }
    }
});
System.register("src/user.decoder", [], function(exports_8, context_8) {
    "use strict";
    var __moduleName = context_8 && context_8.id;
    var UserDecoder;
    return {
        setters:[],
        execute: function() {
            UserDecoder = (function () {
                function UserDecoder() {
                    this.decodeJwt = function (jwtToken) {
                        var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;
                        var matches = idTokenPartsRegex.exec(jwtToken);
                        if (!matches || matches.length < 4) {
                            throw new Error("Failed to decode Jwt token. The token has in valid format. Actual token: '" + jwtToken + "'");
                        }
                        var crackedToken = {
                            header: matches[1],
                            JWSPayload: matches[2],
                            JWSSig: matches[3]
                        };
                        return crackedToken;
                    };
                    this.base64DecodeStringUrlSafe = function (base64IdToken) {
                        // html5 should support atob function for decoding
                        base64IdToken = base64IdToken.replace(/-/g, '+').replace(/_/g, '/');
                        if (window.atob) {
                            return decodeURIComponent(escape(window.atob(base64IdToken))); // jshint ignore:line
                        }
                        else {
                            return decodeURIComponent(escape(this.decodeBase64(base64IdToken)));
                        }
                    };
                }
                UserDecoder.prototype.decode = function (encoded) {
                    var jwtDecoded = this.decodeJwt(encoded);
                    if (!jwtDecoded) {
                        throw Error('Failed to decode value. Value has invalid format.');
                    }
                    var decodedPayLoad = this.safeDecodeBase64(jwtDecoded.JWSPayload);
                    var user = JSON.parse(decodedPayLoad);
                    //if (!user || !user.hasOwnProperty('aud')) throw new Error('');
                    return user;
                };
                UserDecoder.prototype.safeDecodeBase64 = function (value) {
                    var base64Decoded = this.base64DecodeStringUrlSafe(value);
                    if (!base64Decoded) {
                        //this.info('The returned id_token could not be base64 url safe decoded.');
                        throw Error('Failed to base64 decode value. Value has invalid format.');
                    }
                    return base64Decoded;
                };
                UserDecoder.prototype.decodeBase64 = function (base64IdToken) {
                    var codes = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
                    base64IdToken = String(base64IdToken).replace(/=+$/, '');
                    var length = base64IdToken.length;
                    if (length % 4 === 1) {
                        throw new Error('The token to be decoded is not correctly encoded.');
                    }
                    var h1, h2, h3, h4, bits, c1, c2, c3, decoded = '';
                    for (var i = 0; i < length; i += 4) {
                        //Every 4 base64 encoded character will be converted to 3 byte string, which is 24 bits
                        // then 6 bits per base64 encoded character
                        h1 = codes.indexOf(base64IdToken.charAt(i));
                        h2 = codes.indexOf(base64IdToken.charAt(i + 1));
                        h3 = codes.indexOf(base64IdToken.charAt(i + 2));
                        h4 = codes.indexOf(base64IdToken.charAt(i + 3));
                        // For padding, if last two are '='
                        if (i + 2 === length - 1) {
                            bits = h1 << 18 | h2 << 12 | h3 << 6;
                            c1 = bits >> 16 & 255;
                            c2 = bits >> 8 & 255;
                            decoded += String.fromCharCode(c1, c2);
                            break;
                        }
                        else if (i + 1 === length - 1) {
                            bits = h1 << 18 | h2 << 12;
                            c1 = bits >> 16 & 255;
                            decoded += String.fromCharCode(c1);
                            break;
                        }
                        bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;
                        // then convert to 3 byte chars
                        c1 = bits >> 16 & 255;
                        c2 = bits >> 8 & 255;
                        c3 = bits & 255;
                        decoded += String.fromCharCode(c1, c2, c3);
                    }
                    return decoded;
                };
                ;
                UserDecoder.prototype.isEmpty = function (str) {
                    return (typeof str === 'undefined' || !str || 0 === str.length);
                };
                ;
                return UserDecoder;
            }());
            exports_8("UserDecoder", UserDecoder);
        }
    }
});
System.register("src/adal.config", [], function(exports_9, context_9) {
    "use strict";
    var __moduleName = context_9 && context_9.id;
    var AdalConfig;
    return {
        setters:[],
        execute: function() {
            AdalConfig = (function () {
                function AdalConfig(clientId, tenant, redirectUri, postLogoutRedirectUrl) {
                    this.clientId = clientId;
                    this.tenant = tenant;
                    this.redirectUri = redirectUri;
                    this.postLogoutRedirectUrl = postLogoutRedirectUrl;
                }
                ;
                return AdalConfig;
            }());
            exports_9("AdalConfig", AdalConfig);
        }
    }
});
System.register("src/aad.logout.url.builder", [], function(exports_10, context_10) {
    "use strict";
    var __moduleName = context_10 && context_10.id;
    var AadLogoutUrlBuilder;
    return {
        setters:[],
        execute: function() {
            AadLogoutUrlBuilder = (function () {
                function AadLogoutUrlBuilder() {
                    this.postLogoutRedirectUri = window.location.href;
                }
                AadLogoutUrlBuilder.prototype.with = function (tenant, postLogoutRedirectUri) {
                    this.tenant = tenant;
                    this.postLogoutRedirectUri = postLogoutRedirectUri || this.postLogoutRedirectUri;
                    return this;
                };
                AadLogoutUrlBuilder.prototype.build = function () {
                    var urlNavigate = AadLogoutUrlBuilder.MicrosoftLoginUrl + this.tenant + '/oauth2/logout?';
                    urlNavigate = urlNavigate + 'post_logout_redirect_uri=' + encodeURIComponent(this.postLogoutRedirectUri);
                    return urlNavigate;
                };
                AadLogoutUrlBuilder.MicrosoftLoginUrl = 'https://login.microsoftonline.com/';
                return AadLogoutUrlBuilder;
            }());
            exports_10("AadLogoutUrlBuilder", AadLogoutUrlBuilder);
        }
    }
});
System.register("src/authentication.context", ["src/constants"], function(exports_11, context_11) {
    "use strict";
    var __moduleName = context_11 && context_11.id;
    var constants_1;
    var AuthenticationContext;
    return {
        setters:[
            function (constants_1_1) {
                constants_1 = constants_1_1;
            }],
        execute: function() {
            AuthenticationContext = (function () {
                function AuthenticationContext(config, storage, navigator, guidGenerator, aadUrlBuilder, userDecoder, logoutUrlBuilder) {
                    this.CONSTANTS = constants_1.Constants;
                    this.REQUEST_TYPES = constants_1.RequestTypes;
                    this.storage = storage;
                    this.navigator = navigator;
                    this.config = config;
                    this.guidGenerator = guidGenerator;
                    this.aadUrlBuilder = aadUrlBuilder;
                    this.userDecoder = userDecoder;
                    this.logoutUrlBuilder = logoutUrlBuilder;
                }
                AuthenticationContext.prototype.login = function () {
                    if (this.loginInProgress) {
                        this.info("Login in progress");
                        return;
                    }
                    var urlConfig = this.cloneConfig(this.config);
                    urlConfig.nonce = this.guidGenerator.generate();
                    urlConfig.state = this.guidGenerator.generate();
                    this.verbose('Expected state: ' + urlConfig.state + ' startPage:' + window.location);
                    this.storage.setItem(this.CONSTANTS.STORAGE.LOGIN_REQUEST, window.location);
                    this.storage.setItem(this.CONSTANTS.STORAGE.STATE_LOGIN, urlConfig.state);
                    this.storage.setItem(this.CONSTANTS.STORAGE.NONCE_IDTOKEN, urlConfig.nonce);
                    this.storage.setItem(this.CONSTANTS.STORAGE.LOGIN_ERROR, '');
                    this.storage.setItem(this.CONSTANTS.STORAGE.ERROR, '');
                    this.storage.setItem(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
                    var url = this.aadUrlBuilder.with(urlConfig).build();
                    this.navigator.navigate(url);
                    this.loginInProgress = true;
                };
                AuthenticationContext.prototype.getUser = function () {
                    var idtoken = this.storage.getItem(constants_1.Constants.STORAGE.IDTOKEN);
                    try {
                        var user = this.userDecoder.decode(idtoken);
                        return user;
                    }
                    catch (error) {
                        if (console && console.debug)
                            console.debug('getUser() returns null on catched error. Details >> ' + error.toString());
                        return null;
                    }
                };
                AuthenticationContext.prototype.getToken = function () {
                    return this.storage.getItem(constants_1.Constants.STORAGE.IDTOKEN);
                };
                AuthenticationContext.prototype.logout = function () {
                    var idtoken = this.storage.getItem(constants_1.Constants.STORAGE.IDTOKEN);
                    if (idtoken === '')
                        return null;
                    this.storage.setItem(this.CONSTANTS.STORAGE.NONCE_IDTOKEN, '');
                    this.storage.setItem(this.CONSTANTS.STORAGE.STATE_LOGIN, '');
                    this.storage.setItem(this.CONSTANTS.STORAGE.IDTOKEN, '');
                    var url = this.logoutUrlBuilder.with(this.config.tenant, this.config.postLogoutRedirectUrl).build();
                    this.navigator.navigate(url);
                };
                AuthenticationContext.prototype.verbose = function (message) {
                };
                AuthenticationContext.prototype.info = function (message) {
                };
                AuthenticationContext.prototype.createOptions = function () {
                    return {
                        nonce: this.idTokenNonce,
                        tenant: this.config.tenant,
                        clientId: this.config.clientId
                    };
                };
                AuthenticationContext.prototype.cloneConfig = function (obj) {
                    if (null === obj || 'object' !== typeof obj) {
                        return obj;
                    }
                    var copy = {};
                    for (var attr in obj) {
                        if (obj.hasOwnProperty(attr)) {
                            copy[attr] = obj[attr];
                        }
                    }
                    return copy;
                };
                ;
                return AuthenticationContext;
            }());
            exports_11("AuthenticationContext", AuthenticationContext);
        }
    }
});
System.register("src/local.storage", [], function(exports_12, context_12) {
    "use strict";
    var __moduleName = context_12 && context_12.id;
    var LocalStorage;
    return {
        setters:[],
        execute: function() {
            LocalStorage = (function () {
                function LocalStorage() {
                }
                LocalStorage.prototype.setItem = function (key, value) {
                    localStorage.setItem(key, value);
                };
                LocalStorage.prototype.getItem = function (key) {
                    return localStorage.getItem(key);
                };
                return LocalStorage;
            }());
            exports_12("LocalStorage", LocalStorage);
        }
    }
});
System.register("src/query.string.deserializer", ["src/constants"], function(exports_13, context_13) {
    "use strict";
    var __moduleName = context_13 && context_13.id;
    var constants_2;
    var QueryStringDeserializer;
    function hasAadProps(deserializedHash) {
        return (deserializedHash.hasOwnProperty(constants_2.Constants.ERROR_DESCRIPTION) ||
            deserializedHash.hasOwnProperty(constants_2.Constants.ACCESS_TOKEN) ||
            deserializedHash.hasOwnProperty(constants_2.Constants.ID_TOKEN));
    }
    exports_13("hasAadProps", hasAadProps);
    return {
        setters:[
            function (constants_2_1) {
                constants_2 = constants_2_1;
            }],
        execute: function() {
            QueryStringDeserializer = (function () {
                function QueryStringDeserializer() {
                    this.plRegex = /\+/g;
                }
                QueryStringDeserializer.prototype.deserialize = function (queryString) {
                    queryString = this.trimHashSign(queryString);
                    var match;
                    // Regex for replacing addition symbol with a space
                    var searchRegex = /([^&=]+)=([^&]*)/g;
                    var obj = {};
                    match = searchRegex.exec(queryString);
                    while (match) {
                        obj[this.decode(match[1])] = this.decode(match[2]);
                        match = searchRegex.exec(queryString);
                    }
                    return obj;
                };
                QueryStringDeserializer.prototype.decode = function (s) {
                    return decodeURIComponent(s.replace(this.plRegex, ' '));
                };
                QueryStringDeserializer.prototype.trimHashSign = function (hash) {
                    if (hash.indexOf('#/') > -1) {
                        hash = hash.substring(hash.indexOf('#/') + 2);
                    }
                    else if (hash.indexOf('#') > -1) {
                        hash = hash.substring(1);
                    }
                    return hash;
                };
                return QueryStringDeserializer;
            }());
            exports_13("QueryStringDeserializer", QueryStringDeserializer);
        }
    }
});
System.register("src/aad.redirect.url", ["src/constants"], function(exports_14, context_14) {
    "use strict";
    var __moduleName = context_14 && context_14.id;
    var constants_3;
    var AadRedirectUrl;
    return {
        setters:[
            function (constants_3_1) {
                constants_3 = constants_3_1;
            }],
        execute: function() {
            AadRedirectUrl = (function () {
                function AadRedirectUrl(object) {
                    this.object = object;
                }
                Object.defineProperty(AadRedirectUrl.prototype, "idToken", {
                    get: function () {
                        return this.object[constants_3.Constants.ID_TOKEN];
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(AadRedirectUrl.prototype, "expiresIn", {
                    get: function () {
                        return this.object[constants_3.Constants.EXPIRES_IN];
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(AadRedirectUrl.prototype, "accesToken", {
                    get: function () {
                        return this.object[constants_3.Constants.ACCESS_TOKEN];
                    },
                    enumerable: true,
                    configurable: true
                });
                Object.defineProperty(AadRedirectUrl.prototype, "sessionState", {
                    get: function () {
                        return this.object[constants_3.Constants.SESSION_STATE];
                    },
                    enumerable: true,
                    configurable: true
                });
                AadRedirectUrl.prototype.isAadRedirect = function () {
                    return (this.object.hasOwnProperty(constants_3.Constants.ERROR_DESCRIPTION) ||
                        this.object.hasOwnProperty(constants_3.Constants.ACCESS_TOKEN) ||
                        this.object.hasOwnProperty(constants_3.Constants.ID_TOKEN));
                };
                return AadRedirectUrl;
            }());
            exports_14("AadRedirectUrl", AadRedirectUrl);
        }
    }
});
System.register("src/aad.redirect.processor", ["src/constants", "src/aad.redirect.url"], function(exports_15, context_15) {
    "use strict";
    var __moduleName = context_15 && context_15.id;
    var constants_4, aad_redirect_url_1;
    var AadRedirectProcessor;
    return {
        setters:[
            function (constants_4_1) {
                constants_4 = constants_4_1;
            },
            function (aad_redirect_url_1_1) {
                aad_redirect_url_1 = aad_redirect_url_1_1;
            }],
        execute: function() {
            AadRedirectProcessor = (function () {
                function AadRedirectProcessor(queryStringDeserializer, userDecoder, storage, window) {
                    this.queryStringDeserializer = queryStringDeserializer;
                    this.userDecoder = userDecoder;
                    this.storage = storage;
                    this.window = window;
                }
                AadRedirectProcessor.prototype.process = function () {
                    var deserializedHash = this.queryStringDeserializer.deserialize(this.window.location.hash);
                    var aadRedirect = new aad_redirect_url_1.AadRedirectUrl(deserializedHash);
                    if (aadRedirect.isAadRedirect()) {
                        var userProfile = this.userDecoder.decode(aadRedirect.idToken);
                        this.storage.setItem(constants_4.Constants.STORAGE.IDTOKEN, aadRedirect.idToken);
                        this.window.location.assign(this.storage.getItem(constants_4.Constants.STORAGE.LOGIN_REQUEST));
                    }
                    return aadRedirect.isAadRedirect();
                };
                return AadRedirectProcessor;
            }());
            exports_15("AadRedirectProcessor", AadRedirectProcessor);
        }
    }
});
System.register("src/authentication", ["src/authentication.context", "src/local.storage", "src/navigator", "src/aad.url.builder", "src/guid.generator", "src/user.decoder", "src/aad.redirect.processor", "src/query.string.deserializer", "src/aad.logout.url.builder"], function(exports_16, context_16) {
    "use strict";
    var __moduleName = context_16 && context_16.id;
    var authentication_context_1, local_storage_1, navigator_1, aad_url_builder_1, guid_generator_1, user_decoder_1, aad_redirect_processor_1, query_string_deserializer_1, aad_logout_url_builder_1;
    var Authentication;
    return {
        setters:[
            function (authentication_context_1_1) {
                authentication_context_1 = authentication_context_1_1;
            },
            function (local_storage_1_1) {
                local_storage_1 = local_storage_1_1;
            },
            function (navigator_1_1) {
                navigator_1 = navigator_1_1;
            },
            function (aad_url_builder_1_1) {
                aad_url_builder_1 = aad_url_builder_1_1;
            },
            function (guid_generator_1_1) {
                guid_generator_1 = guid_generator_1_1;
            },
            function (user_decoder_1_1) {
                user_decoder_1 = user_decoder_1_1;
            },
            function (aad_redirect_processor_1_1) {
                aad_redirect_processor_1 = aad_redirect_processor_1_1;
            },
            function (query_string_deserializer_1_1) {
                query_string_deserializer_1 = query_string_deserializer_1_1;
            },
            function (aad_logout_url_builder_1_1) {
                aad_logout_url_builder_1 = aad_logout_url_builder_1_1;
            }],
        execute: function() {
            Authentication = (function () {
                function Authentication() {
                }
                Authentication.getContext = function (configuration) {
                    console.log('getContext...');
                    var context = new authentication_context_1.AuthenticationContext(configuration, new local_storage_1.LocalStorage(), new navigator_1.Navigator(), new guid_generator_1.GuidGenerator(), new aad_url_builder_1.AadUrlBuilder(new guid_generator_1.GuidGenerator()), new user_decoder_1.UserDecoder(), new aad_logout_url_builder_1.AadLogoutUrlBuilder());
                    //TODO this.enableNativeLogging();
                    return context;
                };
                Authentication.getAadRedirectProcessor = function () {
                    var p = new aad_redirect_processor_1.AadRedirectProcessor(new query_string_deserializer_1.QueryStringDeserializer(), new user_decoder_1.UserDecoder(), new local_storage_1.LocalStorage(), window);
                    return p;
                };
                return Authentication;
            }());
            exports_16("Authentication", Authentication);
        }
    }
});
System.register("index", ["src/authentication", "src/adal.config"], function(exports_17, context_17) {
    "use strict";
    var __moduleName = context_17 && context_17.id;
    function exportStar_1(m) {
        var exports = {};
        for(var n in m) {
            if (n !== "default") exports[n] = m[n];
        }
        exports_17(exports);
    }
    return {
        setters:[
            function (authentication_1_1) {
                exportStar_1(authentication_1_1);
            },
            function (adal_config_1_1) {
                exportStar_1(adal_config_1_1);
            }],
        execute: function() {
        }
    }
});
//# sourceMappingURL=index.js.map