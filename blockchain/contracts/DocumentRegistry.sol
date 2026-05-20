// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DocumentRegistry {
    struct Document {
        string documentHash;
        uint256 timestamp;
        address owner;
    }

    mapping(string => Document) public documents;

    event DocumentStored(string documentHash, uint256 timestamp, address owner);

    function storeDocument(string memory _documentHash) public {
        require(documents[_documentHash].timestamp == 0, "Hash dokumen (Ciphertext) sudah terdaftar!");
        
        documents[_documentHash] = Document({
            documentHash: _documentHash,
            timestamp: block.timestamp,
            owner: msg.sender
        });

        emit DocumentStored(_documentHash, block.timestamp, msg.sender);
    }

    function verifyDocument(string memory _documentHash) public view returns (bool) {
        return documents[_documentHash].timestamp != 0;
    }
}