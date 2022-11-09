var WebSocket = require( 'ws' ).WebSocket;
var browserifyCipher = require( 'browserify-cipher' );
var nobleSecp256k1 = require( 'noble-secp256k1' );
var bitcoinjs = require( 'bitcoinjs-lib' );
var crypto = require( 'crypto' );
var axios = require( 'axios' );
var fs = require( 'fs' );
var bolt11 = require( 'bolt11' );
var request = require( 'request' );

var privKey = "";
var secret = "";

//lnd stuff

const adminmac = "";
const lndendpoint = "https://127.0.0.1:8080";

async function getHodlInvoice( amount, hash, expiry = 40 ) {
  var invoice = "";
  const macaroon = adminmac;
  const endpoint = lndendpoint;
  let requestBody = {
      hash: Buffer.from( hash, "hex" ).toString( "base64" ),
      value: amount.toString(),
      cltv_expiry: expiry.toString(),
  }
  let options = {
    url: endpoint + '/v2/invoices/hodl',
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify( requestBody ),
  }
  process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
  request.post( options, function( error, response, body ) {
    console.log( "body:", body );
    invoice = ( body[ "payment_request" ] );
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( invoice );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var invoice_i_seek = await isNoteSetYet( invoice );
            return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function cancelHodlInvoice( hash ) {
  var canceled = "";
  const macaroon = adminmac;
  const endpoint = lndendpoint;
  let requestBody = {
      payment_hash: Buffer.from( hash, "hex" ).toString( "base64" ),
  }
  let options = {
    url: endpoint + '/v2/invoices/cancel',
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify( requestBody ),
  }
  process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
  request.post( options, function( error, response, body ) {
    console.log( "body:", body );
    if ( typeof( body ) == "object" && Object.keys( body ).length == 0 ) {
        canceled = "true";
    } else {
        canceled = "false";
    }
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( canceled );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var info_i_seek = await isNoteSetYet( canceled );
            return info_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function settleHoldInvoice( preimage ) {
  var settled = "";
  const macaroon = adminmac;
  const endpoint = lndendpoint;
  let requestBody = {
      preimage: Buffer.from( preimage, "hex" ).toString( "base64" )
  }
  let options = {
    url: endpoint + '/v2/invoices/settle',
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify( requestBody ),
  }
  process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
  request.post( options, function( error, response, body ) {
    if ( typeof( body ) == "object" && Object.keys( body ).length == 0 ) {
        settled = "true";
    } else {
        settled = "false";
    }
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( settled );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var invoice_i_seek = await isNoteSetYet( settled );
            return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;   
}

function getInvoiceSoftExpiry( invoice ) {
    var decoded = bolt11.decode( invoice );
    if ( decoded[ "timeExpireDate" ] ) {
        return decoded[ "timeExpireDate" ] - decoded[ "timestamp" ];
    } else {
        return 3600;
    }
}

async function getinvoicestatus( hash ) {
  var status = "";
  const macaroon = adminmac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
  request.get( options, function( error, response, body ) {
    status = body[ "state" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( status );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( status );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

function getinvoicepmthash( invoice ) {
    var decoded = bolt11.decode( invoice );
    var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
        if ( decoded[ "tags" ][ i ][ "tagName" ] == "payment_hash" ) {
            var pmthash = decoded[ "tags" ][ i ][ "data" ].toString();
        }
    }
    return pmthash;
}

async function getInvoiceAmount( hash ) {
  var amount = "";
  const macaroon = adminmac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
  request.get( options, function( error, response, body ) {
    amount = body[ "value" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( amount );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( amount );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

function get_amount_i_am_asked_to_pay( invoice ) {
    var decoded = bolt11.decode( invoice );
    var amount = decoded[ "satoshis" ].toString();
    return amount;
}

function get_hard_expiry_of_invoice_i_am_asked_to_pay( invoice ) {
    var decoded = bolt11.decode( invoice );
    var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
        if ( decoded[ "tags" ][ i ][ "tagName" ] == "min_final_cltv_expiry" ) {
            var cltv_expiry = decoded[ "tags" ][ i ][ "data" ].toString();
        }
    }
    return cltv_expiry;
}

async function payInvoiceAndSettleWithPreimage( invoice ) {
    var preimage = "";
    var users_pmthash = getinvoicepmthash( invoice );
    var state_of_held_invoice_with_that_hash = await getinvoicestatus( users_pmthash );
    if ( state_of_held_invoice_with_that_hash != "ACCEPTED" ) {
        return "nice try, asking me to pay an invoice without compensation: " + state_of_held_invoice_with_that_hash;
    }
    var amount_i_will_receive = await getInvoiceAmount( users_pmthash );
    var amount_i_am_asked_to_pay = get_amount_i_am_asked_to_pay( invoice );
    if ( Number( amount_i_will_receive ) < Number( amount_i_am_asked_to_pay ) ) {
        return "nice try, asking me to send more than I will receive as compensation";
    }
    //use the creation date of the invoice that pays me to estimate the block when that invoice was created
    //do that by getting the current unix timestamp, the current blockheight, and the invoice creation timestamp,
    var invoice_creation_timestamp = await getInvoiceCreationTimestamp( users_pmthash );
    invoice_creation_timestamp = Number( invoice_creation_timestamp );
    var current_unix_timestamp = Number( Math.floor( Date.now() / 1000 ) );
    var current_blockheight = await getBlockheight();
    current_blockheight = Number( current_blockheight );
    //then subtract X units of 600 seconds from the current timestamp til it is less than the invoice creation timestmap,
    var units_of_600 = 0;
    var i; for ( i=0; i<1008; i++ ) {
        var interim_unix_timestamp = current_unix_timestamp - ( ( ( units_of_600 ) + 1 ) * 600 );
        units_of_600 = units_of_600 + 1
        if ( interim_unix_timestamp < invoice_creation_timestamp ) {
            break;
        }
    }
    //then subtract X from the current blockheight to get an estimated block when my invoice was created, then add 900 to it
    //assign the result to a variable called block_when_i_consider_the_invoice_that_pays_me_to_expire
    var block_when_i_consider_the_invoice_that_pays_me_to_expire = ( current_blockheight - units_of_600 ) + 900;
    //get the current blockheight and, to it, add the cltv_expiry value of the invoice I am asked to pay (should be 40 usually)
    //assign the result to a variable called block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire
    var expiry_of_invoice_that_pays_me = await getInvoiceHardExpiry( users_pmthash );
    var expiry_of_invoice_i_am_asked_to_pay = await get_hard_expiry_of_invoice_i_am_asked_to_pay( invoice );
    var block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire = current_blockheight + Number( expiry_of_invoice_i_am_asked_to_pay );
    //abort if block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire > block_when_i_consider_the_invoice_that_pays_me_to_expire
    if ( Number( block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire ) > Number( block_when_i_consider_the_invoice_that_pays_me_to_expire ) ) {
        return "nice try, asking me to pay you when the invoice that pays me is about to expire";
    }
    //because that would mean the recipient can hold my payment til after the invoice that pays me expires
    //then he could settle my payment to him but leave me unable to reimburse myself (because the invoice that pays me expired)
    //also, when sending my payment, remember to set the cltv_limit value
    //it should be positive and equal to block_when_i_consider_the_invoice_that_pays_me_to_expire - current_blockheight
    var cltv_limit = block_when_i_consider_the_invoice_that_pays_me_to_expire - current_blockheight;
    var adminmacaroon = adminmac;
    var endpoint = lndendpoint;
    let requestBody = {
        payment_request: invoice,
        fee_limit: {"fixed": "500"},
        allow_self_payment: true,
        cltv_limit: Number( cltv_limit )
    }
    let options = {
        url: endpoint + '/v1/channels/transactions',
        json: true,
        headers: {
          'Grpc-Metadata-macaroon': adminmacaroon,
        },
        form: JSON.stringify( requestBody ),
    }
    process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
    request.post( options, function( error, response, body ) {
        preimage = ( body[ "payment_preimage" ] );
    });
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( data_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isDataSetYet( preimage );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( preimage );
        return data_i_seek;
    }
    var preimage_for_settling_invoice_that_pays_me = await getTimeoutData();
        if ( preimage_for_settling_invoice_that_pays_me != "" ) {
            preimage_for_settling_invoice_that_pays_me = Buffer.from( preimage_for_settling_invoice_that_pays_me, "base64" ).toString( "hex" );
            console.log( "preimage that pays me:", preimage_for_settling_invoice_that_pays_me );
            settleHoldInvoice( preimage_for_settling_invoice_that_pays_me );
            returnable = '{"status": "success","preimage":"' + preimage_for_settling_invoice_that_pays_me + '"}';
        } else {
            returnable = '{"status": "failure"}';
        }
    return returnable;
}

async function getInvoiceCreationTimestamp( hash ) {
  var timestamp = "";
  const macaroon = adminmac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
  request.get( options, function( error, response, body ) {
    timestamp = body[ "creation_date" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( timestamp );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( timestamp );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function getBlockheight() {
    return new Promise( function( resolve, reject ) {
        request( "https://mempool.space/api/blocks/tip/height", function( error, response, body ) {
            if ( !error && response.statusCode >= 200 && response.statusCode < 300 ) {
                resolve( body );
            }
        });
    });
}

async function getInvoiceHardExpiry( hash ) {
  var expiry = "";
  const macaroon = adminmac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  process.env[ "NODE_TLS_REJECT_UNAUTHORIZED" ] = 0;
  request.get( options, function( error, response, body ) {
    expiry = body[ "cltv_expiry" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( expiry );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( expiry );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

//end of lnd stuff

if ( fs.existsSync( "keys.txt" ) ) {
        var keystext = fs.readFileSync( "keys.txt" ).toString();
        var keys = JSON.parse( keystext );
        privKey = keys[ 0 ];
        secret = keys[ 1 ];
} else {
        privKey = Buffer.from( nobleSecp256k1.utils.randomPrivateKey() ).toString( "hex" );
        secret = Buffer.from( nobleSecp256k1.utils.randomPrivateKey() ).toString( "hex" );
        var keys = [ privKey, secret ];
        var texttowrite = JSON.stringify( keys );
        fs.writeFileSync( "keys.txt", texttowrite, function() {return;});
}

if ( fs.existsSync( "contracts.txt" ) ) {
        var contractstext = fs.readFileSync( "contracts.txt" ).toString();
        var contracts = JSON.parse( contractstext );
} else {
        var contracts = [];
        var texttowrite = JSON.stringify( contracts );
        fs.writeFileSync( "contracts.txt", texttowrite, function() {return;});
}

var pubKeyMinus2 = nobleSecp256k1.getPublicKey( privKey, true ).substring( 2 );
var signing_pubkey = nobleSecp256k1.getPublicKey( privKey, true );
console.log( "nostr pubkey:", pubKeyMinus2 );
console.log( "signing pubkey:", signing_pubkey );
var randomid = Buffer.from( nobleSecp256k1.utils.randomPrivateKey() ).toString( "hex" );

var bitcoin_price = 0;

function rmd160( string ) {
        return crypto.createHash( "ripemd160" ).update( string ).digest( "hex" );
}

function sha256( string ) {
        return crypto.createHash( "sha256" ).update( string ).digest( "hex" );
}

function hash160( string ) {
        return rmd160( Buffer.from( sha256( string ), "hex" ) );
}

function isValidInvoice( invoice ) {
        try{
                return ( typeof( bolt11.decode( invoice ) ) == "object" );
        } catch( e ) {
                return false;
        }
}

function normalizeRelayURL(e){let[t,...r]=e.trim().split("?");return"http"===t.slice(0,4)&&(t="ws"+t.slice(4)),"ws"!==t.slice(0,2)&&(t="wss://"+t),t.length&&"/"===t[t.length-1]&&(t=t.slice(0,-1)),[t,...r].join("?")}

function encrypt( privkey, pubkey, text ) {
        var keystext = fs.readFileSync( "keys.txt" ).toString();
        var keys = JSON.parse( keystext );
        privKey = keys[ 0 ];
        var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );

        var iv = Uint8Array.from( crypto.randomBytes( 16 ) )
        var cipher = browserifyCipher.createCipheriv(
                'aes-256-cbc',
                Buffer.from( key, 'hex' ),
                iv
        );
        var encryptedMessage = cipher.update( text, "utf8", "base64" );
        emsg = encryptedMessage + cipher.final( "base64" );

        return emsg + "?iv=" + Buffer.from( iv.buffer ).toString( "base64");
}

function decrypt( privkey, pubkey, ciphertext ) {
        var keystext = fs.readFileSync( "keys.txt" ).toString();
        var keys = JSON.parse( keystext );
        privKey = keys[ 0 ];
        var [ emsg, iv ] = ciphertext.split( "?iv=" );
        var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );

        var decipher = browserifyCipher.createDecipheriv(
                'aes-256-cbc',
                Buffer.from( key, "hex" ),
                Buffer.from( iv, "base64" )
        );
        var decryptedMessage = decipher.update( emsg, "base64" );
        dmsg = decryptedMessage + decipher.final( "utf8" );

        return dmsg;
}

async function getNote( id ) {
        var relay = "wss://relay.damus.io";
        relay = normalizeRelayURL( relay );
        var socket = new WebSocket( relay );
        var note = "";
        socket.on( 'message', async function( event ) {
                var event = JSON.parse( event );
                if ( event[ 2 ] && event[ 2 ].kind == 4 && event[ 2 ].pubkey == pubKeyMinus2 ) {
                        var i; for ( i=0; i<event[ 2 ].tags.length; i++ ) {
                                if ( event[ 2 ].tags[ i ] && event[ 2 ].tags[ i ][ 1 ] ) {
                                        var recipient = event[ 2 ].tags[ i ][ 1 ];
                                        if ( recipient == pubKeyMinus2 ) {
                                                var decrypted_message = decrypt( privKey, event[ 2 ].pubkey, event[ 2 ].content );
                                                if ( id != event[ 2 ].id ) {
                                                        return;
                                                } else {
                                                        note = ( decrypted_message );
                                                }
                                        } else if ( event[ 2 ].pubkey == pubKeyMinus2 ) {
                                                note = ( decrypt( privKey, recipient, event[ 2 ].content ) );
                                        }
                                }
                        }
                } else if ( event[ 2 ] && ( event[ 2 ].kind == 1 || event[ 2 ].kind == 4239 ) ) {
                        note = ( event[ 2 ].content );
                }
        });
        socket.on( 'open', function open() {
                var filter = {
                        "ids": [
                                id
                        ]
                }
                var subscription = [ "REQ", randomid, filter ];
                subscription = JSON.stringify( subscription );
                var chaser = [ "CLOSE", randomid ];
                chaser = JSON.stringify( chaser );
                socket.send( subscription );
                setTimeout( function() {socket.send( chaser );}, 1000 );
                setTimeout( function() {socket.terminate();}, 2000 );
        });
        async function isNoteSetYet( note_i_seek ) {
                return new Promise( function( resolve, reject ) {
                        if ( note_i_seek == "" ) {
                                setTimeout( async function() {
                                        var msg = await isNoteSetYet( note );
                                        resolve( msg );
                                }, 100 );
                        } else {
                                resolve( note_i_seek );
                        }
                });
        }
        async function getTimeoutData() {
                var note_i_seek = await isNoteSetYet( note );
                return note_i_seek;
        }
        var returnable = await getTimeoutData();
        return returnable;
}

async function sendDM( note, recipient ) {
        var relay = "wss://relay.damus.io";
        relay = normalizeRelayURL( relay );
        var socket = new WebSocket( relay );
        var id = "";
        socket.on( 'open', function open() {
                function makePrivateNote( note, recipientpubkey ) {
                        var now = Math.floor( ( new Date().getTime() ) / 1000 );
                        var privatenote = encrypt( privKey, recipientpubkey, note );
                        var newevent = [
                                0,
                                pubKeyMinus2,
                                now,
                                20004,
                                [['p', recipientpubkey]],
                                privatenote
                        ];
                        var message = JSON.stringify( newevent );
                        var msghash = sha256( message );
                        nobleSecp256k1.schnorr.sign( msghash, privKey ).then(
                                value => {
                                        sig = value;
                                        nobleSecp256k1.schnorr.verify(
                                                sig,
                                                msghash,
                                                pubKeyMinus2
                                        ).then(
                                                value => {
                                                        if ( value ) {
                                                                var fullevent = {
                                                                        "id": msghash,
                                                                        "pubkey": pubKeyMinus2,
                                                                        "created_at": now,
                                                                        "kind": 20004,
                                                                        "tags": [['p', recipientpubkey]],
                                                                        "content": privatenote,
                                                                        "sig": sig
                                                                }
                                                                var sendable = [ "EVENT", fullevent ];
                                                                sendable = JSON.stringify( sendable );
                                                                socket.send( sendable );
                                                                id = msghash;
                                                                setTimeout( function() {socket.terminate();}, 300 );
                                                         }
                                                }
                                       );
                                }
                        );
                }
                makePrivateNote( note, recipient );
        });
        async function isNoteSetYet( note_i_seek ) {
            return new Promise( function( resolve, reject ) {
                    if ( note_i_seek == "" ) {
                            setTimeout( async function() {
                                    var msg = await isNoteSetYet( id );
                                    resolve( msg );
                            }, 100 );
                    } else {
                            resolve( note_i_seek );
                    }
            });
        }
        async function getTimeoutData() {
            var note_i_seek = await isNoteSetYet( id );
            return note_i_seek;
        }
        var returnable = await getTimeoutData();
        return returnable;
}

async function setPublicNote( note ) {
        var relay = "wss://relay.damus.io";
        relay = normalizeRelayURL( relay );
        var socket = new WebSocket( relay );
        var id = "";
        socket.on( 'open', function open() {
                function makePublicNote( note ) {
                        var now = Math.floor( ( new Date().getTime() ) / 1000 );
                        var newevent = [
                                0,
                                pubKeyMinus2,
                                now,
                                1,
                                [],
                                note
                        ];
                        var message = JSON.stringify( newevent );
                        var msghash = sha256( message );
                        nobleSecp256k1.schnorr.sign( msghash, privKey ).then(
                                value => {
                                        sig = value;
                                        nobleSecp256k1.schnorr.verify(
                                                sig,
                                                msghash,
                                                pubKeyMinus2
                                        ).then(
                                                value => {
                                                        if ( value ) {
                                                                var fullevent = {
                                                                        "id": msghash,
                                                                        "pubkey": pubKeyMinus2,
                                                                        "created_at": now,
                                                                        "kind": 1,
                                                                        "tags": [],
                                                                        "content": note,
                                                                        "sig": sig
                                                                }
                                                                var sendable = [ "EVENT", fullevent ];
                                                                sendable = JSON.stringify( sendable );
                                                                socket.send( sendable );
                                                                id = msghash;
                                                                setTimeout( function() {socket.terminate();}, 300 );
                                                         }
                                                }
                                       );
                                }
                        );
                }
                makePublicNote( note );
        });
        async function isNoteSetYet( note_i_seek ) {
            return new Promise( function( resolve, reject ) {
                    if ( note_i_seek == "" ) {
                            setTimeout( async function() {
                                    var msg = await isNoteSetYet( id );
                                    resolve( msg );
                            }, 100 );
                    } else {
                            resolve( note_i_seek );
                    }
            });
        }
        async function getTimeoutData() {
            var note_i_seek = await isNoteSetYet( id );
            return note_i_seek;
        }
        var returnable = await getTimeoutData();
        return returnable;
}

async function handleMessage( event ) {
        var event = JSON.parse( event );
        if ( event[ 2 ] && ( event[ 2 ].kind == 4 || event[ 2 ].kind == 20004 ) ) {
                //console.log( "tags length:", event[ 2 ].tags.length );
                var i; for ( i=0; i<event[ 2 ].tags.length; i++ ) {
                        //console.log( "tags length:", event[ 2 ].tags.length );
                        if ( event[ 2 ].tags[ i ] && event[ 2 ].tags[ i ][ 1 ] ) {
                                var recipient = event[ 2 ].tags[ i ][ 1 ];
                                if ( recipient == pubKeyMinus2 ) {
                                        var decrypted_message = decrypt( privKey, event[ 2 ].pubkey, event[ 2 ].content );
                                        var note = ( decrypted_message );
                                        console.log( note );
                                        var reply = await handleNote( note, event[ 2 ].pubkey );
                                        console.log( reply );
                                        if ( reply ) {
                                                var id = await sendDM( JSON.stringify( reply ), event[ 2 ].pubkey );
                                                console.log( id );
                                        }
                                }
                        }
                }
        }
}

function openConnection( socket ) {
        console.log( "connected" );
        function checkHeartbeat( socket ) {
            heartbeat = false;
            var heartbeatsubId   = Buffer.from( nobleSecp256k1.utils.randomPrivateKey() ).toString( "hex" );
            var heartbeatfilter  = { "ids": [ "41ce9bc50da77dda5542f020370ecc2b056d8f2be93c1cedf1bf57efcab095b0" ] }
            var heartbeatsub     = [ "REQ", heartbeatsubId, heartbeatfilter ];
            if ( socket && socket.readyState != 0 ) {
                    socket.send( JSON.stringify( heartbeatsub ) );
            }
            setTimeout( function() {
                    if ( !heartbeat && ( socket.readyState == 3 || socket.readyState == 0 ) ) {
                            socket.terminate();
                            socket.removeAllListeners();
                            //socket.removeEventListener( 'message', handleMessage );
                            //socket.removeEventListener( 'open', function() {openConnection( socket );} );
                            var relay = "wss://relay.damus.io";
                            socket = new WebSocket( relay );
	                    socket.on( 'error', ( error ) => { console.log( error ); });
                            socket.on( 'message', handleMessage );
                            socket.on( 'open', function() {openConnection( socket );} );
                    }
            }, 2000 );
            setTimeout( function() {checkHeartbeat( socket );}, 5000 );
        }
        checkHeartbeat( socket );
        var filter = {
                "#p": [
                        pubKeyMinus2
                ],
                "since": Math.floor( Date.now() / 1000 ) - ( 60 * 5 )
        }
        var newid = Buffer.from( nobleSecp256k1.utils.randomPrivateKey() ).toString( "hex" );
        var subscription = [ "REQ", newid, filter ];
        subscription = JSON.stringify( subscription );
        socket.send( subscription );
}

async function handlePrivateMessages() {
        var relay = "wss://relay.damus.io";
        relay = normalizeRelayURL( relay );
        var socket = new WebSocket( relay );
        socket.on( 'error', ( error ) => { console.log( error ); });
        socket.on( 'message', handleMessage );
        socket.on( 'open', function() {openConnection( socket );} );
        doBackgroundTasks( 12 );
}

async function handlePublicMessages( pubkey, subscription_id, oracle_hash, creatorkey, goal, timestamp ) {
        var relay = "wss://relay.damus.io";
        relay = normalizeRelayURL( relay );
        var socket = new WebSocket( relay );
        var subId2   = subscription_id;
        var filter2  = { "#p": [ pubkey ] }
        var subscription2 = [ "REQ", subId2, filter2 ];
        socket.on( 'message', async function( event ) {
                var event = JSON.parse( event );
                if ( event[ 2 ] && event[ 2 ].kind == 4239 ) {
                        var content = event[ 2 ].content;
                        if ( !isValidJson( content ) ) return;
                        var json = JSON.parse( content );
                        console.log( "json:", json );
                }
        });
        socket.on( 'open', function open() {
                socket.send( JSON.stringify( subscription2 ) );
        });
        var chaser = [ "CLOSE", randomid ];
        chaser = JSON.stringify( chaser );
        setTimeout( function() {socket.send( chaser );}, 1000 );
        setTimeout( function() {socket.terminate();}, 3000 );
        console.log( "closed" );
}

async function handleNote( content, pubkey ) {
        try {
                var json = JSON.parse( content );
        } catch ( e ) {
                console.log( "bad json:", json );
                return false;  
        }
        var keystext = fs.readFileSync( "keys.txt" ).toString();
        var keys = JSON.parse( keystext );
        privKey = keys[ 0 ];
        secret = keys[ 1 ];
        if ( json[ "type" ] && json[ "content" ] ) {
                if ( json[ "type" ] == "be my oracle" ) {
                        var contractstext = fs.readFileSync( "contracts.txt" ).toString();
                        var contracts = JSON.parse( contractstext );
                        var contract_id = sha256( JSON.stringify( json[ "content" ] ) );
                        if ( contract_id in contracts ) {
                                console.log( "oh no! They resent you a contract that already exists! Aborting" );
                                return;
                        }
                        if ( getInvoiceSoftExpiry( json[ "content" ][ "shorters_invoice" ] ) < 1209600 || getInvoiceSoftExpiry( json[ "content" ][ "longers_invoice" ] ) < 1209600 ) {
                                console.log( "oh no! They sent you invoices that expire too soon! Aborting" );
                                return;
                        }
                        if ( !( json[ "content" ][ "longers_invoice" ] && json[ "content" ][ "shorters_invoice" ] && json[ "content" ][ "sats_deposit" ] && json[ "content" ][ "longers_key" ] && json[ "content" ][ "shorters_key" ] && json[ "content" ][ "shorters_liquidation_price" ] && json[ "content" ][ "timestamp_of_start" ] && json[ "content" ][ "smallest_low_side_price" ] && json[ "content" ][ "smallest_high_side_price" ] && json[ "content" ][ "dollar_value" ] && json[ "content" ][ "longers_bitcoin_address" ] && json[ "content" ][ "longers_liquidation_price" ] && json[ "content" ][ "shorters_bitcoin_address" ] ) ) {
                                console.log( "oh no! They didn't send you everything!", json[ "content" ][ "longers_invoice" ] && json[ "content" ][ "shorters_invoice" ] && json[ "content" ][ "sats_deposit" ] && json[ "content" ][ "longers_key" ] && json[ "content" ][ "shorters_key" ] && json[ "content" ][ "shorters_liquidation_price" ] && json[ "content" ][ "timestamp_of_start" ] && json[ "content" ][ "smallest_low_side_price" ] && json[ "content" ][ "smallest_high_side_price" ] && json[ "content" ][ "dollar_value" ] && json[ "content" ][ "longers_bitcoin_address" ] && json[ "content" ][ "longers_liquidation_price" ] && json[ "content" ][ "shorters_bitcoin_address" ] );
                                return;
                        }
                        if ( !isValidInvoice( json[ "content" ][ "longers_invoice" ] ) || !isValidInvoice( json[ "content" ][ "shorters_invoice" ] ) ) {
                                console.log( "oh no, they didn't give you valid invoices! Aborting" );
                                return;
                        }
                        if ( typeof( json[ "content" ][ "sats_deposit" ] ) != "number" || typeof( json[ "content" ][ "shorters_liquidation_price" ] ) != "number" || typeof( json[ "content" ][ "longers_liquidation_price" ] ) != "number" || typeof( json[ "content" ][ "timestamp_of_start" ] ) != "number" || typeof( json[ "content" ][ "smallest_low_side_price" ] ) != "number" || typeof( json[ "content" ][ "smallest_high_side_price" ] ) != "number" || typeof( json[ "content" ][ "dollar_value" ] ) != "number" ) {
                                console.log( "oh no, something they gave you that was supposed to be a number was not a number! Aborting" );
                                return;
                        }
                        if ( String( json[ "content" ][ "timestamp_of_start" ] ).length != 10 ) {
                                console.log( "oh no, they gave you an invalid timestamp! Aborting. What they gave you:", json[ "content" ][ "timestamp_of_start" ] );
                                return;
                        }
                        var now = Math.floor( Date.now() / 1000 );
                        if ( json[ "content" ][ "timestamp_of_start" ] < now - 172800 ) {
                                console.log( "oh no, they started their contract more than two days ago! Aborting." );
                                return;
                        }
                        if ( isNaN( get_hard_expiry_of_invoice_i_am_asked_to_pay( json[ "content" ][ "longers_invoice" ] ) ) || isNaN( get_hard_expiry_of_invoice_i_am_asked_to_pay( json[ "content" ][ "shorters_invoice" ] ) ) || Number( get_hard_expiry_of_invoice_i_am_asked_to_pay( json[ "content" ][ "longers_invoice" ] ) ) > 40 || Number( get_hard_expiry_of_invoice_i_am_asked_to_pay( json[ "content" ][ "shorters_invoice" ] ) ) > 40 ) {
                                console.log( "oh no, they gave you an invoice with too long a hard expiry! Aborting." );
                                return;
                        }
                        var longer_liquidation = Number( ( ( 100000000 * json[ "content" ][ "dollar_value" ] ) / ( Number( json[ "content" ][ "sats_deposit" ] ) + Number( json[ "content" ][ "sats_deposit" ] - 546 ) ) ).toFixed( 2 ) );
                        var shorter_liquidation = Number( ( ( 100000000 * json[ "content" ][ "dollar_value" ] ) / 546 ).toFixed( 2 ) );
                        if ( longer_liquidation != json[ "content" ][ "longers_liquidation_price" ] || shorter_liquidation != json[ "content" ][ "shorters_liquidation_price" ] ) {
                                console.log( "oh no, they gave you at least one bad liquidation price! Aborting" );
                                return;
                        }
                        var low_side = Number( ( ( 100000000 * json[ "content" ][ "dollar_value" ] ) / ( Number( json[ "content" ][ "sats_deposit" ] ) + 546 ) ).toFixed( 2 ) );
                        var high_side = Number( ( ( 100000000 * json[ "content" ][ "dollar_value" ] ) / ( Number( json[ "content" ][ "sats_deposit" ] ) - 546 ) ).toFixed( 2 ) );
                        if ( low_side != json[ "content" ][ "smallest_low_side_price" ] || high_side != json[ "content" ][ "smallest_high_side_price" ] ) {
                                console.log( "oh no, they gave you at least one bad payment triggering price! Aborting" );
                                return;
                        }
                        var longers_hash = getinvoicepmthash( json[ "content" ][ "longers_invoice" ] );
                        var shorters_hash = getinvoicepmthash( json[ "content" ][ "shorters_invoice" ] );
                        var longers_amt = get_amount_i_am_asked_to_pay( json[ "content" ][ "longers_invoice" ] );
                        var shorters_amt = get_amount_i_am_asked_to_pay( json[ "content" ][ "shorters_invoice" ] );
                        if ( longers_amt != shorters_amt || longers_amt != json[ "content" ][ "sats_deposit" ] ) {
                                console.log( "oh no, the amounts don't match! Aborting" );
                                return;
                        }
                        var oracles_long_invoice = await getHodlInvoice( longers_amt, longers_hash, 1152 );
                        var oracles_short_invoice = await getHodlInvoice( shorters_amt, shorters_hash, 1152 );
                        var message_to_sign = `I am the oracle in a "contract for difference" with this id: ${contract_id} between the people with these pubkeys: ${json[ "content" ][ "longers_key" ]} and ${json[ "content" ][ "shorters_key" ]}. This is my "long" lightning invoice: ${oracles_long_invoice}. It is conditional on this invoice being paid: ${json[ "content" ][ "longers_invoice" ]}, the latter invoice belonging to the person going long in this contract. If an attempt is made to pay my long invoice (presumably by the person going short), I will delay forwarding the payment until one of two things happens, a timestamp arrives or a price arrives. The price is this: $${json[ "content" ][ "shorters_liquidation_price" ]} If that price arrives before the contract terminates, it means the person going short should be liquidated, and I will try to do that by forwarding the payment of the person going short to the person going long – if he or she is online and cooperates. The timestamp is this: ${json[ "content" ][ "timestamp_of_start" ] + 604800} If that timestamp arrives without anyone getting liquidated first, I will then choose to either settle it (as long as the person going long cooperates) or cancel it. I will cancel it in one of two circumstances. The first is if the price of bitcoin is lower than $${json[ "content" ][ "smallest_low_side_price" ]}. The person going short should get their money back in that case so I will cancel their payment to the person going long. The second circumstance is if the price of bitcoin is higher than $${json[ "content" ][ "smallest_high_side_price" ]} and I see a proof that the person going short proves they paid the person going long an amount of money that I deem sufficient to ensure that the person going short only walks away with $${json[ "content" ][ "dollar_value" ]}, and the person going long gets the difference. The proof can take one of two forms: first, it can be a payment to this bitcoin address: ${json[ "content" ][ "longers_bitcoin_address" ]}, or, second, it can be a lightning preimage for an invoice created by the person going long with the description "difference." If neither of those circumstances is true, I will not cancel the payment of (presumably) the person going short, instead I will try to forward the payment to the person going long, settling both invoices in the process. This is my "short" lightning invoice: ${oracles_short_invoice}. It is conditional on this invoice being paid: ${json[ "content" ][ "shorters_invoice" ]}, the latter invoice belonging to the person going short in this contract. If an attempt is made to pay my "short" invoice (presumably by the person going long), I will delay forwarding the payment until one of two things happens, a timestamp arrives or a price arrives. The price is this: $${json[ "content" ][ "longers_liquidation_price" ]} If that price arrives before the contract terminates, it means the person going long should be liquidated, and I will try to do that by forwarding the payment of the person going long to the person going short – if he or she is online and cooperates. The timestamp is this: ${json[ "content" ][ "timestamp_of_start" ] + 604800} If that timestamp arrives without anyone getting liquidated first, I will then choose to either settle it (as long as the person going short cooperates) or cancel it. I will cancel it in one of two circumstances. The first is if the price of bitcoin is higher than $${json[ "content" ][ "smallest_high_side_price" ]}. The person going long should get their money back in that case so I will cancel their payment to the person going short. The second circumstance is if the price of bitcoin is lower than $${json[ "content" ][ "smallest_low_side_price" ]} and I see a proof that the person going long proves they paid the person going short an amount of money that I deem sufficient to ensure that the person going short walks away with $${json[ "content" ][ "dollar_value" ]}. The proof can take one of two forms: first, it can be a payment to this bitcoin address: ${json[ "content" ][ "shorters_bitcoin_address" ]}, or, second, it can be a lightning preimage for an invoice created by the person going short with the description "difference." If neither of those circumstances is true, I will not cancel the payment of (presumably) the person going long, instead I will try to forward the payment to the person going short, settling both invoices in the process.`;
                        var hash_of_message = sha256( message_to_sign );
                        var sig = await nobleSecp256k1.sign( hash_of_message, privKey );
                        var message = {}
                        message[ "type" ] = "I'll be your oracle";
                        var content = {}
                        content = {}
                        content[ "contract_id" ] = contract_id;
                        content[ "sig" ] = sig;
                        content[ "oracles_long_invoice" ] = oracles_long_invoice;
                        content[ "oracles_short_invoice" ] = oracles_short_invoice;
                        message[ "content" ] = content;
                        contracts[ contract_id ] = json[ "content" ];
                        var texttowrite = JSON.stringify( contracts );
                        fs.writeFileSync( "contracts.txt", texttowrite, function() {return;});
                        return message;
                }
                if ( json[ "type" ] == "get invoice status" ) {
                        var message = {}
                        message[ "type" ] = "invoice status";
                        var status = await getinvoicestatus( json[ "content" ] );
                        if ( status == undefined ) {status = "bad_payment_hash";}
                        var contractstext = fs.readFileSync( "contracts.txt" ).toString();
                        var contracts = JSON.parse( contractstext );
                        Object.keys( contracts ).forEach( async function( contract_id ) {
                                if ( "settlement_invoice" in contracts[ contract_id ] && getinvoicepmthash( contracts[ contract_id ][ "settlement_invoice" ] ) == json[ "content" ] ) {
                                        var status = await getinvoicestatus( json[ "content" ] );
                                        if ( status == "ACCEPTED" ) {
                                                console.log( "I am supposed to pay the winning invoice of this contract:", contract_id, "because the status of the corresponding invoice is:", status );
                                                if ( contracts[ contract_id ][ "loser" ] == contracts[ contract_id ][ "longers_key" ] ) {
                                                        var hash = getinvoicepmthash( contracts[ contract_id ][ "shorters_invoice" ] );
                                                } else {
                                                        var hash = getinvoicepmthash( contracts[ contract_id ][ "longers_invoice" ] );
                                                }
                                                var canceled = await cancelHodlInvoice( hash );
                                                if ( canceled == "true" ) {
                                                        console.log( "ok the winner's payment was canceled, now I just need to pay the winner and reimburse myself" );
                                                        var returnable = await payInvoiceAndSettleWithPreimage( contracts[ contract_id ][ "settlement_invoice" ] );
                                                        console.log( "I got reimbursed! Here is the preimage:", returnable );
                                                        //todo: If this payment does not go through the oracle should tell the winner to
                                                        //get some inbound capacity in an amount greater than or equal to the value of the
                                                        //payment and link them to where they can do that, then tell them to try again
                                                }
                                        }
                                }
                        });
                        var content = {}
                        content[ "hash" ] = json[ "content" ];
                        content[ "status" ] = status;
                        message[ "content" ] = content;
                        return message;
                }
                if ( json[ "type" ] == "settlement" ) {
                        var contractstext = fs.readFileSync( "contracts.txt" ).toString();
                        var contracts = JSON.parse( contractstext );
                        var contract_id = json[ "content" ];
                        if ( !( contract_id in contracts ) ) {
                                console.log( "oh no! They asked you about the status of a contract that does not exist! Aborting" );
                                return;
                        }
                        var contract = contracts[ contract_id ];
                        var end = contract[ "timestamp_of_start" ] + 604800;
                        var now = Math.floor( Date.now() / 1000 );
                        //todo: make it run only under two conditions: one, if both parties agree to it, or two, if the end date is in the past, rather than right now during testing, where it only runs if the end date is in the future and only *stop* (as seen on the line below) if the current time is later than the end date, i.e. the end date is before the current time, i.e. the end date is in the past
                        //if ( now < end ) {
                        if ( now > end ) {
                                console.log( "oh no! They asked you to settle a contract that is still in progress! Aborting" );
                                return;
                        }
                        if ( Number( bitcoin_price ) > contract[ "starting_price" ] ) {
                                console.log( "actual price:", Number( bitcoin_price ), "needed price:", contract[ "smallest_high_side_price" ] );
                                //tell the shorter how much they owe the longer
                                var hash = getinvoicepmthash( contract[ "shorters_invoice" ] );
                                var canceled = await cancelHodlInvoice( hash );
                                if ( canceled == "true" ) {
                                        console.log( "yay, the longer's payment to the shorter was canceled because the longer won because the price was higher than the starting price! Current price:", Number( bitcoin_price ), "Starting price:", contract[ "starting_price" ] );
                                }
                                var sats_deserved_by_shorter = ( contract[ "dollar_value" ] / Number( bitcoin_price ) ).toFixed( 8 ) * 100000000;
                                var sats_deposited = contract[ "sats_deposit" ];
                                var difference = Math.abs( sats_deserved_by_shorter - sats_deposited );
                                contracts[ contract_id ][ "settlement_amount" ] = Math.round( difference );
                                contracts[ contract_id ][ "winner" ] = contract[ "longers_key" ];
                                contracts[ contract_id ][ "loser" ] = contract[ "shorters_key" ];
                                var texttowrite = JSON.stringify( contracts );
                                fs.writeFileSync( "contracts.txt", texttowrite, function() {return;});
                                console.log( "here is the what the shorter owes the longer:", Math.round( difference ) );
                                var message_to_shorter = {}
                                message_to_shorter[ "type" ] = "send to longer";
                                message_to_shorter[ "content" ] = Math.round( difference );
                                var id1 = await sendDM( JSON.stringify( message_to_shorter ), contract[ "shorters_key" ] );
                                console.log( "message to shorter:", id1 );
                                var message_to_longer = {}
                                message_to_longer[ "type" ] = "get from shorter";
                                message_to_longer[ "content" ] = Math.round( difference );
                                var id2 = await sendDM( JSON.stringify( message_to_longer ), contract[ "longers_key" ] );
                                console.log( "message to longer:", id2 );
                        }
                        if ( Number( bitcoin_price ) < contract[ "starting_price" ] ) {
                                //tell the longer how much they owe the shorter
                                var hash = getinvoicepmthash( contract[ "longers_invoice" ] );
                                var canceled = await cancelHodlInvoice( hash );
                                if ( canceled == "true" ) {
                                        console.log( "yay, the shorter's payment to the longer was canceled because the shorter won because the price was lower than the starting price! Current price:", Number( bitcoin_price ), "Starting price:", contract[ "starting_price" ] );
                                }
                                var sats_deserved_by_shorter = ( contract[ "dollar_value" ] / Number( bitcoin_price ) ).toFixed( 8 ) * 100000000;
                                var sats_deposited = contract[ "sats_deposit" ];
                                var difference = Math.abs( sats_deserved_by_shorter - sats_deposited );
                                contracts[ contract_id ][ "settlement_amount" ] = Math.round( difference );
                                contracts[ contract_id ][ "winner" ] = contract[ "shorters_key" ];
                                contracts[ contract_id ][ "loser" ] = contract[ "longers_key" ];
                                var texttowrite = JSON.stringify( contracts );
                                fs.writeFileSync( "contracts.txt", texttowrite, function() {return;});
                                console.log( "here is the what the longer owes the shorter:", Math.round( difference ) );
                                var message_to_shorter = {}
                                message_to_shorter[ "type" ] = "get from longer";
                                message_to_shorter[ "content" ] = Math.round( difference );
                                var id1 = await sendDM( JSON.stringify( message_to_shorter ), contract[ "shorters_key" ] );
                                console.log( "message to shorter:", id1 );
                                var message_to_longer = {}
                                message_to_longer[ "type" ] = "send to shorter";
                                message_to_longer[ "content" ] = Math.round( difference );
                                var id2 = await sendDM( JSON.stringify( message_to_longer ), contract[ "longers_key" ] );
                                console.log( "message to longer:", id2 );
                        }
                        return false;
                }
                if ( json[ "type" ] == "settlement invoice" ) {
                        var contractstext = fs.readFileSync( "contracts.txt" ).toString();
                        var contracts = JSON.parse( contractstext );
                        var contract_id = json[ "content" ][ "hash" ];
                        if ( !( contract_id in contracts ) ) {
                                console.log( "oh no! They asked you about the status of a contract that does not exist! Aborting" );
                                return;
                        }
                        var contract = contracts[ contract_id ];
                        if ( pubkey != contract[ "winner" ] ) return;
                        console.log( "yay, the winner wants their payment, here is their invoice:", json[ "content" ][ "settlement_invoice" ] );
                        if ( !isValidInvoice( json[ "content" ][ "settlement_invoice" ] ) ) {
                                //todo: send the person who owes money their money back because the would-be recipient is trying something fishy
                                console.log( "oh no, they didn't give you a valid settlement invoice! Aborting" );
                                return;
                        }
                        var settlement_hash = getinvoicepmthash( json[ "content" ][ "settlement_invoice" ] );
                        var settlement_amt = get_amount_i_am_asked_to_pay( json[ "content" ][ "settlement_invoice" ] );
                        if ( settlement_amt != contract[ "settlement_amount" ] ) {
                                console.log( "oh no, the amounts don't match! Aborting" );
                                return;
                        }
                        var settlement_hodl_invoice = await getHodlInvoice( settlement_amt, settlement_hash );
                        console.log( "settlement hodl invoice:", settlement_hodl_invoice );
                        contracts[ contract_id ][ "settlement_invoice" ] = json[ "content" ][ "settlement_invoice" ];
                        var texttowrite = JSON.stringify( contracts );
                        fs.writeFileSync( "contracts.txt", texttowrite, function() {return;});
                        var message_to_loser = {}
                        message_to_loser[ "type" ] = "time to settle";
                        message_to_loser[ "content" ] = settlement_hodl_invoice;
                        sendDM( JSON.stringify( message_to_loser ), contract[ "loser" ] );
                        return false;
                }
                if ( json[ "type" ] == "force win" ) {
                        //todo: each party should show up when the contract ends. If they are the first one there, they should see
                        //a screen telling them to wait for their counterparty for up to 1 hour, and it should show a countdown.
                        //If their counterparty shows up, the winner should run the settle function and everything should go well
                        //If their counterparty does not respond at some point, including by not showing up at all, then the winner
                        //should run forceWin() when 1 hour has passed. An oracle that detects a forceWin() call should check if
                        //the person calling it really won. If so, they should cancel their payment to the loser and ask them for
                        //an invoice for the value of the loser's payment, then pay that. If it does not go through the oracle
                        //should tell them to get some inbound capacity in an amount greater than or equal to the value of the
                        //payment and link them to where they can do that, then tell them to try again
                        var contractstext = fs.readFileSync( "contracts.txt" ).toString();
                        var contracts = JSON.parse( contractstext );
                        var contract_id = json[ "content" ][ "contract_id" ];
                        var settlement_invoice = json[ "content" ][ "settlement_invoice" ];
                        if ( !( contract_id in contracts ) ) {
                                console.log( "oh no! They asked you about the status of a contract that does not exist! Aborting" );
                                return;
                        }
                        var contract = contracts[ contract_id ];
                        if ( !isValidInvoice( settlement_invoice ) ) {
                                //todo: if the winner sent this bad invoice, send the loser their money back because the winner's doing something fishy
                                console.log( "oh no, they didn't give you a valid settlement invoice! Aborting" );
                                return;
                        }
                        var force_end = contract[ "timestamp_of_start" ] + 604800 + 3600;
                        var now = Math.floor( Date.now() / 1000 );
                        //todo: make it run only if the time of the force_end is in the future, rather than right now during testing, where it only runs if the time of the force_end is in the past
                        //if ( force_end > now ) {
                        if ( now > force_end ) {
                                console.log( "oh no! They asked you to settle a contract that is still in progress! Aborting" );
                                return;
                        }
                        if ( Number( bitcoin_price ) > contract[ "starting_price" ] ) {
                                console.log( "actual price:", Number( bitcoin_price ), "needed price:", contract[ "smallest_high_side_price" ] );
                                var hash = getinvoicepmthash( contract[ "shorters_invoice" ] );
                                var canceled = await cancelHodlInvoice( hash );
                                if ( canceled == "true" ) {
                                        console.log( "yay, the longer's payment to the shorter was canceled because the longer won because the price was higher than the starting price! Current price:", Number( bitcoin_price ), "Starting price:", contract[ "starting_price" ] );
                                }
                                var sats_deserved_by_shorter = ( contract[ "dollar_value" ] / Number( bitcoin_price ) ).toFixed( 8 ) * 100000000;
                                var sats_deposited = contract[ "sats_deposit" ];
                                var difference = Math.abs( sats_deserved_by_shorter - sats_deposited );
                                if ( !contract[ "winner" ] ) {
                                        contracts[ contract_id ][ "settlement_amount" ] = Math.round( difference );
                                        contracts[ contract_id ][ "winner" ] = contract[ "longers_key" ];
                                        contracts[ contract_id ][ "loser" ] = contract[ "shorters_key" ];
                                        contracts[ contract_id ][ "force_settle" ] = true;
                                        var texttowrite = JSON.stringify( contracts );
                                        fs.writeFileSync( "contracts.txt", texttowrite, function() {return;});
                                        console.log( "here is the what the shorter owes the longer:", Math.round( difference ) );
                                }
                        }
                        if ( Number( bitcoin_price ) < contract[ "starting_price" ] ) {
                                var hash = getinvoicepmthash( contract[ "longers_invoice" ] );
                                var canceled = await cancelHodlInvoice( hash );
                                if ( canceled == "true" ) {
                                        console.log( "yay, the shorter's payment to the longer was canceled because the shorter won because the price was lower than the starting price! Current price:", Number( bitcoin_price ), "Starting price:", contract[ "starting_price" ] );
                                }
                                var sats_deserved_by_shorter = ( contract[ "dollar_value" ] / Number( bitcoin_price ) ).toFixed( 8 ) * 100000000;
                                var sats_deposited = contract[ "sats_deposit" ];
                                var difference = Math.abs( sats_deserved_by_shorter - sats_deposited );
                                if ( !contract[ "winner" ] ) {
                                        contracts[ contract_id ][ "settlement_amount" ] = Math.round( difference );
                                        contracts[ contract_id ][ "winner" ] = contract[ "shorters_key" ];
                                        contracts[ contract_id ][ "loser" ] = contract[ "longers_key" ];
                                        contracts[ contract_id ][ "force_settle" ] = true;
                                        var texttowrite = JSON.stringify( contracts );
                                        fs.writeFileSync( "contracts.txt", texttowrite, function() {return;});
                                        console.log( "here is the what the longer owes the shorter:", Math.round( difference ) );
                                }
                        }
                        if ( pubkey != contract[ "winner" ] ) return;
                        var returnable = await payInvoiceAndSettleWithPreimage( settlement_invoice );
                        console.log( "I got reimbursed! Here is the preimage:", returnable );
                }
        }
        return false;
}

function isHex( string ) {
    regexp = /^[0-9a-fA-F]+$/;
    if ( regexp.test( string ) ) {
        return true;
    } else {
        return false;
    }
}

function isValidJson( content ) {
        try {  
                var json = JSON.parse( content );
        } catch ( e ) {
                return false;  
        }
        return true;
}

async function doBackgroundTasks( i ) {
        //check bitcoin's price every 60 seconds
        if ( i == 12 ) {
                bitcoin_price = await getBitcoinPrice();
                i = 0;
        } else {
                i = i + 1;
        }
        console.log( "bitcoin price:", bitcoin_price );
        setTimeout( function() {doBackgroundTasks( i );}, 5000 );
}

function getData( url ) {
        return new Promise( function( resolve, reject ) {
                axios
                .get( url )
                .then( res => {
                        resolve( res.data );
                }).catch( function( error ) {
                        console.log( error.message );
                });
        });
}

function postData( url, json ) {
        return new Promise( function( resolve, reject ) {
                axios.post( url, json )
                .then( res => {
                        resolve( res.data );
                }).catch( function( error ) {
                        console.log( error.message );
                });
        });
}

function satsToBitcoin( sats ) {
        return "0." + String( sats ).padStart( 8, "0" );
}

async function getBitcoinPrice() {
        var data = await getData( "https://api.coinbase.com/v2/prices/BTC-USD/spot" );
        var json = data;
        var price = json[ "data" ][ "amount" ];
        return price;
}

function waitSomeSeconds( num ) {
        var num = num.toString() + "000";
        num = Number( num );
        return new Promise( function( resolve, reject ) {
                setTimeout( function() { resolve( "" ); }, num );
        });
}

handlePrivateMessages();
