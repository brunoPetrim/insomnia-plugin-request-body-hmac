const { RSA_PKCS1_OAEP_PADDING } = require('constants');
const crypto = require('crypto');
const {JSONPath} = require('jsonpath-plus');

const replacementContent = 'Will be replaced with HMAC of request body';
const settings = {
  key: null,
  algorithm: null,
  encoding: null,
  jsonPath: null,
  removeWhitespace: false,
  timestamp: null,
  method: null
};

function hmac(content) {
  if (settings.jsonPath) {
    content = JSON.stringify(JSONPath({
      path: settings.jsonPath, 
      json: JSON.parse(content),
      wrap: false
    }));
  }
  if (settings.removeWhitespace) {
    content = JSON.stringify(JSON.parse(content));
  }

  const publicKey = `-----BEGIN PUBLIC KEY-----\n!@#\n-----END PUBLIC KEY-----`;
  const stringToHash = settings.timestamp + settings.method + content;
  const hashContent = crypto.createHash(settings.algorithm).update(stringToHash).digest("hex");
  const key = publicKey.replace("!@#", settings.key);

  let hashBase64 = null;
  try {
      hashBase64 = crypto.publicEncrypt({key: key, padding: crypto.constants.RSA_PKCS1_PADDING}, Buffer.from(hashContent, 'utf8') ).toString('base64');
  } catch(e) {
      alert(e);
  }
  return hashBase64;
}

function replaceWithHMAC(content, body) {
  return content.replace(new RegExp(replacementContent, 'g'), hmac(body))
}

module.exports.templateTags = [{
  name: 'requestbodyhmacbruno',
  displayName: 'Request body HMAC (Bruno version)',
  description: 'HMAC a value or the request body (Bruno version)',
  args: [
    {
      displayName: 'Algorithm',
      type: 'enum',
      options: [
        { displayName: 'MD5', value: 'md5' },
        { displayName: 'SHA1', value: 'sha1' },
        { displayName: 'SHA256', value: 'sha256' },
        { displayName: 'SHA512', value: 'sha512' }
      ]
    },
    {
      displayName: 'Digest Encoding',
      description: 'The encoding of the output',
      type: 'enum',
      options: [
        { displayName: 'Hexadecimal', value: 'hex' },
        { displayName: 'Base64', value: 'base64' }
      ]
    },
    {
      displayName: 'Remove whitespace from JSON',
      description: 'Parse and stringify JSON request body to remove any whitespace',
      type: 'enum',
      options: [
        { displayName: 'No', value: false },
        { displayName: 'Yes', value: true }
      ]
    },
    {
      displayName: 'JSONPath to object that should be hashed',
      description: 'If hashing is to be done only to a part of the request body select it using a JSONPath query. Note: whitespace will be removed before hashing',
      type: 'string',
      placeholder: 'JSONPath (leave empty to not use)'
    },
    {
      displayName: 'Key',
      type: 'string',
      placeholder: 'HMAC Secret Key'
    },
    {
      displayName: 'Message',
      type: 'string',
      placeholder: 'Message to hash (leave empty to use request body)'
    }
  ],
  run(context, algorithm, encoding, removeWhitespace = false, jsonPath = '', key = '', value = '') {
    if (encoding !== 'hex' && encoding !== 'base64') {
      throw new Error(`Invalid encoding ${encoding}. Choices are hex, base64`);
    }

    const valueType = typeof value;
    if (valueType !== 'string') {
      throw new Error(`Cannot hash value of type "${valueType}"`);
    }
    
    settings.key = key;
    settings.algorithm = algorithm;
    settings.encoding = encoding;
    settings.removeWhitespace = removeWhitespace === true || removeWhitespace === 'true';
    settings.jsonPath = jsonPath;
    
    if (value === '') {
      return replacementContent;
    } else {
      return hmac(value);
    }
  }
}];

module.exports.requestHooks = [
  context => {
    settings.method = context.request.getMethod();
    settings.timestamp = context.request.getHeader("timestamp");
    if (context.request.getUrl().indexOf(replacementContent) !== -1) {
      context.request.setUrl(replaceWithHMAC(context.request.getUrl(), context.request.getBodyText()));
    }
    if (context.request.getBodyText().indexOf(replacementContent) !== -1) {
      context.request.setBodyText(replaceWithHMAC(context.request.getBodyText(), context.request.getBodyText()));
    }
    context.request.getHeaders().forEach(h => {
      if (h.value.indexOf(replacementContent) !== -1) {
        context.request.setHeader(h.name, replaceWithHMAC(h.value, context.request.getBodyText()));
      }
    });
    context.request.getParameters().forEach(p => {
      if (p.value.indexOf(replacementContent) !== -1) {
        context.request.setParameter(p.name, replaceWithHMAC(p.value, context.request.getBodyText()));
      }
    });
  }
];