from audioop import add
from doctest import master
from email import header
from json.tool import main
from flask import Flask, redirect, url_for, render_template, request, jsonify
from os import stat
from grpc import ServicerContext, StatusCode
from pyqrllib.pyqrllib import str2bin, hstr2bin, bin2hstr
from binascii import hexlify, a2b_base64
from qrl.crypto.xmss import XMSS

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.OptimizedAddressState import OptimizedAddressState
from qrl.core.PaginatedBitfield import PaginatedBitfield
from qrl.core.Block import Block
from qrl.core.TransactionMetadata import TransactionMetadata
from qrl.core.ChainManager import ChainManager
from qrl.core.GenesisBlock import GenesisBlock
from qrl.core.State import State
from qrl.core.TransactionInfo import TransactionInfo
from qrl.core.txs.TransferTransaction import TransferTransaction
from qrl.core.misc import logger
from qrl.core.node import SyncState, POW
from qrl.core.p2p.p2pfactory import P2PFactory
from qrl.core.qrlnode import QRLNode
from qrl.crypto.misc import sha256
from qrl.generated import qrl_pb2
from qrl.services.PublicAPIService import PublicAPIService
from qrl.generated import qrl_pb2_grpc, qrl_pb2
from google.protobuf.json_format import MessageToJson
from google.protobuf.json_format import MessageToDict
import grpc
import time
import re
import json

app = Flask(__name__)

mainnet_node_public_address = "mainnet-1.automated.theqrl.org:19009"
testnet_node_public_address = "127.0.0.1:19009"
CONNECTION_TIMEOUT = 5

@app.route("/")
def index():
    return render_template("faucet.html")

@app.route("/grpc/mainnet/GetHeight")
def mainnet_GetHeight():
    channel = grpc.insecure_channel(mainnet_node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetHeightReq()
    response = stub.GetHeight(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/testnet/GetHeight")
def testnet_GetHeight():
    peer_grpc_channel = grpc.insecure_channel(testnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    peer_stub = qrl_pb2_grpc.PublicAPIStub(peer_grpc_channel)
    block_height_req = qrl_pb2.GetHeightReq()
    block_height_resp = peer_stub.GetHeight(block_height_req, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(block_height_resp)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/mainnet/GetStats")
def mainnet_GetStats():
    channel = grpc.insecure_channel(mainnet_node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetStatsReq()
    response = stub.GetStats(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/testnet/GetStats")
def testnet_GetStats():
    channel = grpc.insecure_channel(testnet_node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetStatsReq()
    response = stub.GetStats(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/mainnet/GetBalance/<qaddress>")
def mainnet_GetBalance(qaddress):
    binary_qrl_address = bytes(hstr2bin(qaddress[1:]))
    channel = grpc.insecure_channel(testnet_node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetBalanceReq(address=binary_qrl_address)
    response = stub.GetBalance(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/testnet/GetBalance/<qaddress>")
def testnet_GetBalance(qaddress):
    binary_qrl_address = bytes(hstr2bin(qaddress[1:]))
    channel = grpc.insecure_channel(testnet_node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetBalanceReq(address=binary_qrl_address)
    response = stub.GetBalance(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")


@app.route("/grpc/mainnet/GetBlockByNumber/<number>")
def mainnet_GetBlockByNumber(number):
    channel = grpc.insecure_channel(mainnet_node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetBlockByNumberReq(block_number=int(number))
    response = stub.GetBlockByNumber(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/testnet/GetBlockByNumber/<number>")
def testnet_GetBlockByNumber(number):
    channel = grpc.insecure_channel(testnet_node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetBlockByNumberReq(block_number=int(number))
    response = stub.GetBlockByNumber(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")


@app.route("/grpc/mainnet/GetBlock/<headerhash>")
def mainnet_GetBlock(headerhash):
    channel = grpc.insecure_channel(mainnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetBlockReq(header_hash=bytes(hstr2bin(headerhash)))
    response = stub.GetBlock(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/testnet/GetBlock/<headerhash>")
def testnet_GetBlock(headerhash):
    channel = grpc.insecure_channel(testnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetBlockReq(header_hash=bytes(hstr2bin(headerhash)))
    response = stub.GetBlock(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/mainnet/GetOTS/<qaddress>")
def mainnet_GetOTS(qaddress):
    channel = grpc.insecure_channel(mainnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetOTSReq(address=bytes(hstr2bin(qaddress[1:])))
    response = stub.GetOTS(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/testnet/GetOTS/<qaddress>")
def testnet_GetOTS(qaddress):
    channel = grpc.insecure_channel(testnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetOTSReq(address=bytes(hstr2bin(qaddress[1:])))
    response = stub.GetOTS(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")


@app.route("/grpc/mainnet/GetTotalBalance/<qaddress>")
def mainnet_GetTotalBalance(qaddress):
    peer_grpc_channel = grpc.insecure_channel(mainnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    peer_stub = qrl_pb2_grpc.PublicAPIStub(peer_grpc_channel)
    total_Bal_req = qrl_pb2.GetTotalBalanceReq(addresses=[bytes(hstr2bin(str(qaddress[1:])))])
    total_Bal_resp = peer_stub.GetTotalBalance(total_Bal_req, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(total_Bal_resp)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")



@app.route("/grpc/testnet/GetTotalBalance/<qaddress>")
def testnet_GetTotalBalance(qaddress):
    peer_grpc_channel = grpc.insecure_channel(testnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    peer_stub = qrl_pb2_grpc.PublicAPIStub(peer_grpc_channel)
    total_Bal_req = qrl_pb2.GetTotalBalanceReq(addresses=[bytes(hstr2bin(str(qaddress[1:])))])
    total_Bal_resp = peer_stub.GetTotalBalance(total_Bal_req, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(total_Bal_resp)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/grpc/mainnet/GetTransaction/<transaction_hash>")
def mainnet_GetTransaction(transaction_hash):
    channel = grpc.insecure_channel(mainnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetTransactionReq(tx_hash=bytes(hstr2bin(transaction_hash)))
    response = stub.GetTransaction(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")


@app.route("/grpc/testnet/GetTransaction/<transaction_hash>")
def testnet_GetTransaction(transaction_hash):
    channel = grpc.insecure_channel(testnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetTransactionReq(tx_hash=bytes(hstr2bin(transaction_hash)))
    response = stub.GetTransaction(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")


@app.route("/grpc/mainnet/GetMiniTransactionsByAddress/<qaddress>")
def mainnet_GetMiniTransactionsByAddress(qaddress):
    channel = grpc.insecure_channel(mainnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetMiniTransactionsByAddressReq(address=bytes(hstr2bin(qaddress[1:])), item_per_page=100000, page_number=1)
    response = stub.GetMiniTransactionsByAddress(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")


@app.route("/grpc/testnet/GetMiniTransactionsByAddress/<qaddress>")
def testnet_GetMiniTransactionsByAddress(qaddress):
    channel = grpc.insecure_channel(testnet_node_public_address, options=(('grpc.enable_http_proxy', 0),))
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    request = qrl_pb2.GetMiniTransactionsByAddressReq(address=bytes(hstr2bin(qaddress[1:])), item_per_page=100000, page_number=1)
    response = stub.GetMiniTransactionsByAddress(request, timeout=CONNECTION_TIMEOUT)
    dict_obj = MessageToDict(response)
    return app.response_class(json.dumps(dict_obj), mimetype="application/json")

@app.route("/api/faucet", methods=['POST'])
def faucet():
    error = None
    if request.method == 'POST':
        if valid_qaddress(request.form['qaddress']):
            return send_testnet_coins(request.form['qaddress'], request.form['amount'])
        else:
            error = 'Invalid QRL address'
    return render_template('faucet.html', error=error)

def valid_qaddress(request_form):
    if len(request_form) == 79:
        return True
    else:
        return False

def tx_unbase64(tx_json_str):
    tx_json = json.loads(tx_json_str)
    tx_json["publicKey"] = base64tohex(tx_json["publicKey"])
    tx_json["signature"] = base64tohex(tx_json["signature"])
    tx_json["transactionHash"] = base64tohex(tx_json["transactionHash"])
    tx_json["transfer"]["addrsTo"] = [base64tohex(v) for v in tx_json["transfer"]["addrsTo"]]
    return json.dumps(tx_json, indent=True, sort_keys=True)

def base64tohex(data):
    return hexlify(a2b_base64(data))

def send_testnet_coins(addrs_to, amounts):
    print(addrs_to)
    master_addr = None
    bytes_addrs_to = []
    fee = [1000000000]
    message_data = None
    xmss_pk = XMSS.from_extended_seed(hstr2bin("010400bc2f62ec1161bba8eece8b511ce6e38f73254f42f045c08f403b9fb3f101a46d0f2b8d1b6da30c0ad8dd88b356e9022b")).pk
    # if len([addrs_to]) > 1:
    #     for i in addrs_to:
    #         bytes_addrs_to.append(bytes(hstr2bin(i)))
    # elif len([addrs_to]) == 1:
    #     bytes_addrs_to.append(bytes(hstr2bin(addrs_to[1:])))

    shor_amounts = [int(float(str(i) + "e9")) for i in amounts]
    print(type([bytes(hstr2bin(str(addrs_to[1:])))]))
    print(type(shor_amounts))
    print(type(message_data))
    print(type(fee))
    print(type(xmss_pk))
    print(type(master_addr))
    # Q0104008eeaa68d90419bc8401b15882d0bcf6c9190d652923f768cac621b58d7e7c7945d7fc97f
    tx = TransferTransaction.create(addrs_to = [bytes(hstr2bin(str(addrs_to[1:])))],
                                        amounts = shor_amounts,
                                        message_data = message_data,
                                        fee = fee,
                                        xmss_pk= xmss_pk,
                                        master_addr=master_addr)

        # Sign transaction
    src_xmss = XMSS.from_extended_seed(hstr2bin(""))
    src_xmss.set_ots_index(0)
    tx.sign(src_xmss)

        # Print result
    txjson = tx_unbase64(tx.to_json())
    print(txjson)

    if not tx.validate():
        print("It was not possible to validate the signature")
        quit(1)

    print("\nTransaction Blob (signed): \n")
    txblob = tx.pbdata.SerializeToString()
    txblobhex = hexlify(txblob).decode()
    print(txblobhex)

    # Push transaction
    print("Sending to a QRL Node...")
    node_public_address = 'testnet-1.automated.theqrl.org:19009'
    channel = grpc.insecure_channel(node_public_address)
    stub = qrl_pb2_grpc.PublicAPIStub(channel)
    push_transaction_req = qrl_pb2.PushTransactionReq(transaction_signed=tx.pbdata)
    push_transaction_resp = stub.PushTransaction(push_transaction_req, timeout=CONNECTION_TIMEOUT)

    # Print result
    print(push_transaction_resp)
