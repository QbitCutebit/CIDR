from hashlib import sha256

class MerkleWalletData:

    """
        Pembuatan data Wallet, serta hashing data Wallet dengan Kunci Publik Bank
        Sentral
    """
    def __init__(self,uri_wallet,uri_cbpubkey,uri_out):
        self.hashresult=list();
        with open(uri_cbpubkey,"r",encoding='utf-8-sig') as temp_file:
            self.cbpubkeylist= [line.rstrip('\n') for line in temp_file]
        with open(uri_wallet,"r",encoding='utf-8-sig') as temp_file:
            self.walletpubkey= [line.rstrip('\n') for line in temp_file]

        """
        Length of walletpubkey and cbpubkey is assumed to be the same
        """
        for line in range(len(self.cbpubkeylist)):
            self.hashresult.append(sha256((self.walletpubkey[line]+self.cbpubkeylist[line]).encode('utf-8')).hexdigest())
            
        with open(uri_out, "w") as f:
            for s in self.hashresult:
                f.write(str(s) +"\n") 


class MerkleNode:
    """
    Menyimpan Node pada rantai merkle
    """
    def __init__(self, hash):
        self.hash = hash
        self.parent = None
        self.left_child = None
        self.right_child = None

class MerkleTree:

    """
    Menyimpan data Merkle Tree
    """
    def __init__(self, data_chunks):
        self.leaves = []

        for chunk in data_chunks:
            node = MerkleNode(self.compute_hash(chunk))
            self.leaves.append(node)

        self.root = self.build_merkle_tree(self.leaves)

    def build_merkle_tree(self, leaves):
        num_leaves = len(leaves)
        if num_leaves == 1:
            return leaves[0]

        parents = []

        i = 0
        while i < num_leaves:
            left_child = leaves[i]
            right_child = leaves[i + 1] if i + 1 < num_leaves else left_child

            parents.append(self.create_parent(left_child, right_child))

            i += 2

        return self.build_merkle_tree(parents)
    

    def create_parent(self, left_child, right_child):
        parent = MerkleNode(
            self.compute_hash(left_child.hash + right_child.hash))
        parent.left_child, parent.right_child = left_child, right_child
        left_child.parent, right_child.parent = parent, parent
        print("Left child: {}\n \t Right child: {}\n \t\tParent: {}\n".format(
            left_child.hash, right_child.hash, parent.hash))
        return parent
    ###
    
    def get_audit_trail(self, chunk_hash):
        """
        Checks if the leaf exists, and returns the audit trail
        in case it does.
        """
        for leaf in self.leaves:
            if leaf.hash == chunk_hash:
                print("Leaf exists")
                return self.generate_audit_trail(leaf)
        return False

    def generate_audit_trail(self, merkle_node, trail=[]):
        """
        Generates the audit trail in a bottom-up fashion
        """
        if merkle_node == self.root:
            trail.append(merkle_node.hash)
            return trail

        # check if the merkle_node is the left child or the right child
        is_left = merkle_node.parent.left_child == merkle_node
        if is_left:
            # since the current node is left child, right child is
            # needed for the audit trail. We'll need this info later
            # for audit proof.
            trail.append((merkle_node.parent.right_child.hash, not is_left))
            return self.generate_audit_trail(merkle_node.parent, trail)
        else:
            trail.append((merkle_node.parent.left_child.hash, is_left))
            return self.generate_audit_trail(merkle_node.parent, trail)


    @staticmethod
    def compute_hash(data):
        data = data.encode('utf-8')
        return sha256(data).hexdigest()


def verify_audit_trail(chunk_hash, audit_trail):
    """
    Performs the audit-proof from the audit_trail received
    from the trusted server.
    """
    proof_till_now = chunk_hash
    for node in audit_trail[:-1]:
        hash = node[0]
        is_left = node[1]
        if is_left:
            # the order of hash concatenation depends on whether the
            # the node is a left child or right child of its parent
            proof_till_now = MerkleTree.compute_hash(hash + proof_till_now)
        else:
            proof_till_now = MerkleTree.compute_hash(proof_till_now + hash)
        print(proof_till_now)
    
    # verifying the computed root hash against the actual root hash
    return proof_till_now == audit_trail[-1]
