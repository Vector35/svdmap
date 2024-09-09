# SVD Mapper (svdmap)

Support loading SVD files into Binary Ninja.

## Usage

1. Open binary in Binary Ninja
2. Run `Import SVD info` command.
3. Select SVD file (i.e. `TC37XPD.svd`).
4. New segments should now be automatically created for each peripheral along with the structure.

## Configuration

### Enable Bitfield Structuring
As Binary Ninja does not support bitfields, all bitfields will become unions, most will find this undesired so by default
this will be disabled. 

To _enable_ bitfield structuring set `SVDMapper.enableBitfieldStructuring` to **true**.

### Disable Comments

Comments can be displayed poorly in some instances so if that is the case you can turn comments off.

To _disable_ comments set `SVDMapper.enableComments` to **false**.
