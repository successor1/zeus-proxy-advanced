import heapq
from os import stat
from grpc import ServicerContext, StatusCode
from pyqrllib.pyqrllib import str2bin, hstr2bin, bin2hstr

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
import grpc
import time
import re

CONNECTION_TIMEOUT = 5

class NodeCommands:
    def __init__(self):
        self.node_public_address = 'mainnet-1.automated.theqrl.org:19009'
        self.channel = grpc.insecure_channel(self.node_public_address)
        self.stub = qrl_pb2_grpc.PublicAPIStub(self.channel)

    def getHeight(self):
        request = qrl_pb2.GetHeightReq()
        response = self.stub.GetHeight(request, timeout=CONNECTION_TIMEOUT)
        block_height = response.height
        return block_height

    def getBlockByNumberHashHeader(self, number):
        request = qrl_pb2.GetBlockByNumberReq(block_number=number)
        response = self.stub.GetBlockByNumber(request, timeout=CONNECTION_TIMEOUT)
        hash_header = bin2hstr(bytes(response.block.header.hash_header))
        return hash_header
    
    def getBlockByNumberHashHeaderPrev(self, number):
        request = qrl_pb2.GetBlockByNumberReq(block_number=number)
        response = self.stub.GetBlockByNumber(request, timeout=CONNECTION_TIMEOUT)
        hash_header_prev = bin2hstr(bytes(response.block.header.hash_header_prev))
        return hash_header_prev

n = NodeCommands()

class Casino:
    def __init__(self):
        self.address = input("Enter the QRL address you would like your winnings sent to: ")
        self.input = input("Select a number (0-9) or a letter (a-f): ")
        self.block_height = []

    
    def deposit(self):
        casinoAddress = "Q010400b49d2ebb003d69db2a66cc179a87592649d9b83cfb32a1200f72dbc62b4aa4903b4dd322"
        


    def checkHeight(self):
        if re.match("^[0-9a-f]$", self.input):
            self.block_height.append(n.getHeight())
            print("You have chosen: " + self.input + ".\nYou are on block height: " + str(self.block_height[0]))
            c.firstCharCheck()
        else:
            exit()
        
    def firstCharCheck(self):
        print("Waiting for blockheight: " + str(self.block_height[0] + 1))
        while True:
            if n.getHeight() != self.block_height[0] + 1:
                print("Waiting for the outcome..\n" + str(n.getHeight()) + " " + str(self.block_height[0] + 1))
            elif n.getHeight() == self.block_height[0] + 1:
                print("Outcome is.. " + n.getBlockByNumberHashHeader(self.block_height[0] + 1))
                print("\nThe first letter is: " + n.getBlockByNumberHashHeader(self.block_height[0] + 1)[0])
                print("\n Your chosen number or letter is: " + self.input)
                if self.input == n.getBlockByNumberHashHeader(self.block_height[0] + 1)[0]:
                    print("\nYou won!")
                    exit()
                elif self.input != n.getBlockByNumberHashHeader(self.block_height[0] + 1)[0]:
                    print("\nYou lose!") 
                    exit()
            elif n.getHeight() > self.block_height[0] + 1:
                print("Error")
                exit()
            else:
                print("Error")
                exit()
            time.sleep(10)

    def payOut(self):
        pass

c = Casino()
c.deposit
c.checkHeight()