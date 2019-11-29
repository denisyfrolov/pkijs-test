const Pkijs = require('pkijs')
const Asn1js = require('asn1js')
const FS = require('fs')

const cert = FS.readFileSync('ilis.cer').toString()

function decodeCert(pem) {
    const b64 = cert.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '')
    const der = Buffer(b64, 'base64')
    const ber = new Uint8Array(der).buffer
    const asn1 = Asn1js.fromBER(ber)
    return new Pkijs.Certificate({ schema: asn1.result })
}

const rdnmap = {
    "2.5.4.6": "C",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.3": "CN",
    "2.5.4.7": "L",
    "2.5.4.8": "S",
    "2.5.4.12": "T",
    "2.5.4.42": "GN",
    "2.5.4.43": "I",
    "2.5.4.4": "SN",
    "1.2.840.113549.1.9.1": "E-mail"
};

const certificate = decodeCert(cert);

for(const typeAndValue of certificate.issuer.typesAndValues)
{
	let typeval = rdnmap[typeAndValue.type];
	if(typeof typeval === "undefined")
		typeval = typeAndValue.type;
		
	const subjval = typeAndValue.value.valueBlock.value;
    console.log(typeval +'='+ subjval);
}

for(const typeAndValue of certificate.subject.typesAndValues)
{
	let typeval = rdnmap[typeAndValue.type];
	if(typeof typeval === "undefined")
		typeval = typeAndValue.type;
		
	const subjval = typeAndValue.value.valueBlock.value;
	console.log(typeval +'='+ subjval);
}

function bufferToHex (buffer) {
    return Array
        .from (new Uint8Array (buffer))
        .map (b => b.toString (16).padStart (2, "0"))
        .join (" ");
}

console.log(bufferToHex(certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));

//console.log(JSON.stringify(decodeCert(cert), null, 2))

//console.log(JSON.stringify(decodeCert(cert).issuer, null, 2))