import binaryninja
from binaryninja import BinaryView, Settings

from mapper import import_svd


def import_svd_command(bv: BinaryView):
    file_path = binaryninja.get_open_filename_input("SVD File")
    if file_path is None:
        return
    import_svd(bv, file_path)


settings = Settings()

bf_title = "Enable Bitfield Structuring"
bf_description = "Bitfields will be structured as unions"
bf_properties = f'{{"title" : "{bf_title}", "description" : "{bf_description}", "type" : "boolean", "default" : false}}'

comment_title = "Enable Comment Creation"
comment_description = "Create comments from the SVD field descriptions"
comment_properties = f'{{"title" : "{comment_title}", "description" : "{comment_description}", "type" : "boolean", "default" : true}}'

settings.register_group("SVDMapper", "SVD Mapper")
settings.register_setting("SVDMapper.enableBitfieldStructuring", bf_properties)
settings.register_setting("SVDMapper.enableComments", comment_properties)

binaryninja.PluginCommand.register(
    "Import SVD Info",
    "Maps SVD peripherals into the binary view as new segments",
    import_svd_command,
)
