define("src/guid.generator", ["require", "exports"], function (require, exports) {
    "use strict";
    var GuidGenerator = (function () {
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
    exports.GuidGenerator = GuidGenerator;
});
define("src/storage", ["require", "exports"], function (require, exports) {
    "use strict";
});
define("src/constants", ["require", "exports"], function (require, exports) {
    "use strict";
    exports.Constants = {
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
    };
    exports.RequestTypes = {
        LOGIN: 'LOGIN',
        RENEW_TOKEN: 'RENEW_TOKEN',
        UNKNOWN: 'UNKNOWN'
    };
});
define("src/navigator", ["require", "exports"], function (require, exports) {
    "use strict";
    var Navigator = (function () {
        function Navigator() {
        }
        Navigator.prototype.navigate = function (url) {
            window.location.replace(url);
        };
        return Navigator;
    }());
    exports.Navigator = Navigator;
});
define("src/aad.url.config", ["require", "exports"], function (require, exports) {
    "use strict";
});
define("src/aad.url.builder", ["require", "exports"], function (require, exports) {
    "use strict";
    var AadUrlBuilder = (function () {
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
    exports.AadUrlBuilder = AadUrlBuilder;
});
define("src/user", ["require", "exports"], function (require, exports) {
    "use strict";
});
define("src/user.decoder", ["require", "exports"], function (require, exports) {
    "use strict";
    var UserDecoder = (function () {
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
    exports.UserDecoder = UserDecoder;
});
define("src/adal.config", ["require", "exports"], function (require, exports) {
    "use strict";
    var AdalConfig = (function () {
        function AdalConfig(clientId, tenant, redirectUri, postLogoutRedirectUrl) {
            this.clientId = clientId;
            this.tenant = tenant;
            this.redirectUri = redirectUri;
            this.postLogoutRedirectUrl = postLogoutRedirectUrl;
        }
        ;
        return AdalConfig;
    }());
    exports.AdalConfig = AdalConfig;
});
define("src/aad.logout.url.builder", ["require", "exports"], function (require, exports) {
    "use strict";
    var AadLogoutUrlBuilder = (function () {
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
    exports.AadLogoutUrlBuilder = AadLogoutUrlBuilder;
});
define("src/authentication.context", ["require", "exports", "src/constants"], function (require, exports, constants_1) {
    "use strict";
    var AuthenticationContext = (function () {
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
    exports.AuthenticationContext = AuthenticationContext;
});
define("src/local.storage", ["require", "exports"], function (require, exports) {
    "use strict";
    var LocalStorage = (function () {
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
    exports.LocalStorage = LocalStorage;
});
define("src/query.string.deserializer", ["require", "exports", "src/constants"], function (require, exports, constants_2) {
    "use strict";
    var QueryStringDeserializer = (function () {
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
    exports.QueryStringDeserializer = QueryStringDeserializer;
    function hasAadProps(deserializedHash) {
        return (deserializedHash.hasOwnProperty(constants_2.Constants.ERROR_DESCRIPTION) ||
            deserializedHash.hasOwnProperty(constants_2.Constants.ACCESS_TOKEN) ||
            deserializedHash.hasOwnProperty(constants_2.Constants.ID_TOKEN));
    }
    exports.hasAadProps = hasAadProps;
});
define("src/aad.redirect.url", ["require", "exports", "src/constants"], function (require, exports, constants_3) {
    "use strict";
    var AadRedirectUrl = (function () {
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
    exports.AadRedirectUrl = AadRedirectUrl;
});
define("src/aad.redirect.processor", ["require", "exports", "src/constants", "src/aad.redirect.url"], function (require, exports, constants_4, aad_redirect_url_1) {
    "use strict";
    var AadRedirectProcessor = (function () {
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
    exports.AadRedirectProcessor = AadRedirectProcessor;
});
define("src/authentication", ["require", "exports", "src/authentication.context", "src/local.storage", "src/navigator", "src/aad.url.builder", "src/guid.generator", "src/user.decoder", "src/aad.redirect.processor", "src/query.string.deserializer", "src/aad.logout.url.builder"], function (require, exports, authentication_context_1, local_storage_1, navigator_1, aad_url_builder_1, guid_generator_1, user_decoder_1, aad_redirect_processor_1, query_string_deserializer_1, aad_logout_url_builder_1) {
    "use strict";
    var Authentication = (function () {
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
    exports.Authentication = Authentication;
});
define("index", ["require", "exports", "src/authentication", "src/adal.config"], function (require, exports, authentication_1, adal_config_1) {
    "use strict";
    function __export(m) {
        for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
    }
    // export * from './adal.authentication';
    // export * from './adal.authentication.context';
    __export(authentication_1);
    __export(adal_config_1);
});
//# sourceMappingURL=index.js.map