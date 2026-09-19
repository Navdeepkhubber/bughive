# SKILL: deserialization
## Trigger
Base64/binary blobs in cookies/hidden fields/API bodies that look like
serialized objects (magic bytes, ViewState, pickled data).
## Root cause
App deserializes attacker data into live objects; a classpath class has
a dangerous side effect on construction (gadget chain).
## Vectors by language
1. Java: ObjectInputStream on user input -> ysoserial (ROME,
   CommonsCollections, Spring); magic bytes rO0AB.. / 0xACED0005
2. PHP: unserialize() -> PHPGGC; look for O:4:"Name": in cookies/params
3. Python: pickle.loads / yaml.load (not safe_load) -> RCE
4. .NET: ViewState (__VIEWSTATE) w/ leaked machine key, or
   BinaryFormatter/LosFormatter on user input
5. Node: node-serialize's unserialize() -> IIFE RCE via _$$ND_FUNC$$_
6. Ruby: Marshal.load or YAML.load (not safe_load)
## Confirming safely
7. Use a benign DNS/HTTP-callback gadget first, not a destructive one --
   prove execution before escalating to a shell
8. ViewState: check __VIEWSTATEMAC validation first -- disabled means
   trivial tamper; enabled needs a leaked machine key
## Triage
Confirmed RCE -> Critical, always. Gadget-shaped input on an old lib
version, unconfirmed -> High.
