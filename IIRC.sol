pragma abicoder v2;
pragma solidity ^0.7.0;

contract IIRC {

    // BEGIN ERC20 STUFF

    address owner;
    uint256 _totalSupply;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor (uint256 initialSupply) {
        owner = msg.sender;
        _totalSupply = initialSupply;
        balances[owner] = _totalSupply;
    }


    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_value <= balances[msg.sender]);

        balances[msg.sender] = balances[msg.sender] - _value;
        balances[_to] = balances[_to] + _value;

        emit Transfer(msg.sender, _to, _value);

        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowances[_from][msg.sender]);

        allowances[_from][msg.sender] = allowances[_from][msg.sender] - _value;
        balances[_from] = balances[_from] - _value;
        balances[_to] = balances[_to] + _value;

        emit Transfer(_from, _to, _value);

        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value <= balances[msg.sender]);

        allowances[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);

        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowances[_owner][_spender];
    }

    // END ERC20 STUFF

    // BEGIN IIRC STUFF

    struct Point {
        uint256 x;
        uint256 y;
    }

    event Message(address indexed _from, address indexed _to, Point _public_key, bytes16[] _data);

    mapping(address => bool) members;
    mapping(address => Point) publicKeys;
    mapping(address => mapping(address => bool)) friendships;

    modifier isRegistered {
        require(members[msg.sender]);
        _;
    }

    function getOwner() public view returns (address) {
        return owner;
    }

    function register(Point calldata _publicKey) public {
        require(!members[msg.sender]);

        members[msg.sender] = true;
        publicKeys[msg.sender] = _publicKey;

        // Registration reward.
        _totalSupply = _totalSupply + 1;
        balances[msg.sender] = balances[msg.sender] + 1;
    }

    function changePublicKey(Point calldata _publicKey) public isRegistered {
        publicKeys[msg.sender] = _publicKey;
    }

    function getPublicKey(address _member) public view returns (Point memory publicKey) {
        return publicKeys[_member];
    }

    function setFriendState(address _friend, bool _state) public isRegistered {
        friendships[msg.sender][_friend] = _state;
    }

    function message(address _to, Point calldata _publicKey, bytes16[] calldata _data) public isRegistered {
        require(friendships[msg.sender][_to] || msg.sender == owner);
        require(friendships[_to][msg.sender] || msg.sender == owner);

        emit Message(msg.sender, _to, _publicKey, _data);
    }

    // The owner can be messaged without a friendship for a small fee.
    function messageOwner(Point calldata _publicKey, bytes16[] calldata _data) public isRegistered {
        transfer(owner, 1000000000);

        emit Message(msg.sender, owner, _publicKey, _data);
    }

    // END IIRC STUFF

}
