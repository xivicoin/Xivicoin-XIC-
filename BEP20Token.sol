pragma solidity 0.5.16;

import "./Context.sol";
import "./IBEP20.sol";
import "./Ownable.sol";
import "./SafeMath.sol";

contract BEP20Token is Context, IBEP20, Ownable {
  using SafeMath for uint256;

  mapping(address => uint256) private _balances;
  mapping(address => mapping(address => uint256)) private _allowances;
  mapping(address => uint256) private _nonces;

  uint256 private _totalSupply;
  uint8 private _decimals;
  string private _symbol;
  string private _name;

  bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

  bytes32 public DOMAIN_SEPARATOR;

  constructor() public {
    _name = "XIVICOIN";
    _symbol = "XIC";
    _decimals = 18;
    _totalSupply = 21000000000000000000000000;
    _balances[msg.sender] = _totalSupply;

    // Compute the DOMAIN_SEPARATOR during contract deployment
    DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("XIVICOIN")),
        keccak256(bytes("1")),
        56, // Binance Smart Chain Mainnet ID
        address(this)
      )
    );

    emit Transfer(address(0), msg.sender, _totalSupply);
  }

  // Standard BEP-20 functions
  function getOwner() external view returns (address) {
    return owner();
  }

  function decimals() external view returns (uint8) {
    return _decimals;
  }

  function symbol() external view returns (string memory) {
    return _symbol;
  }

  function name() external view returns (string memory) {
    return _name;
  }

  function totalSupply() external view returns (uint256) {
    return _totalSupply;
  }

  function balanceOf(address account) external view returns (uint256) {
    return _balances[account];
  }

  function transfer(address recipient, uint256 amount) external returns (bool) {
    _transfer(_msgSender(), recipient, amount);
    return true;
  }

  function allowance(address owner, address spender) external view returns (uint256) {
    return _allowances[owner][spender];
  }

  function approve(address spender, uint256 amount) external returns (bool) {
    _approve(_msgSender(), spender, amount);
    return true;
  }

  function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
    _transfer(sender, recipient, amount);
    _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "BEP20: transfer amount exceeds allowance"));
    return true;
  }

  function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
    _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
    return true;
  }

  function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
    _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "BEP20: decreased allowance below zero"));
    return true;
  }

  // Permit function for gasless approval
  function permit(
    address owner,
    address spender,
    uint256 amount,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
  ) external {
    require(deadline >= block.timestamp, "BEP20Permit: expired deadline");

    // Calculate the digest to be signed
    bytes32 structHash = keccak256(
      abi.encode(PERMIT_TYPEHASH, owner, spender, amount, _nonces[owner]++, deadline)
    );

    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

    // Recover the signer (the owner) from the signature
    address recovered = ecrecover(digest, v, r, s);
    require(recovered == owner, "BEP20Permit: invalid signature");

    // Call _approve to set the allowance
    _approve(owner, spender, amount);
    emit Approval(owner, spender, amount);
  }

  // Internal functions
  function _transfer(address sender, address recipient, uint256 amount) internal {
    require(sender != address(0), "BEP20: transfer from the zero address");
    require(recipient != address(0), "BEP20: transfer to the zero address");

    _balances[sender] = _balances[sender].sub(amount, "BEP20: transfer amount exceeds balance");
    _balances[recipient] = _balances[recipient].add(amount);
    emit Transfer(sender, recipient, amount);
  }

  function _approve(address owner, address spender, uint256 amount) internal {
    require(owner != address(0), "BEP20: approve from the zero address");
    require(spender != address(0), "BEP20: approve to the zero address");

    _allowances[owner][spender] = amount;
    emit Approval(owner, spender, amount);
  }
}
