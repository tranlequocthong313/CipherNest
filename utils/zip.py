from typing import Optional
import zipfile
import io

from utils.exceptions import RequirePasswordError
from lsb.file import File
from lsb.models import ExtractedPayload
from CipherNest.settings import SECRET_KEY

class Zip:
    def create_zip(self, response_data: ExtractedPayload, password: Optional[str] = None) -> io.BytesIO:
        use_user_password = response_data.is_encrypted()
        use_compression = response_data.is_compressed()

        if use_user_password:
            if not password:
                raise RequirePasswordError()

        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename, filedata in response_data.extracted_files:
                zip_info = zipfile.ZipInfo(filename)
                if use_user_password and use_compression:
                    zip_file.writestr(zip_info, File.decompress_decrypt(password or SECRET_KEY, filedata))
                elif use_user_password:
                    zip_file.writestr(zip_info, File.decrypt(password or SECRET_KEY, filedata))
                elif use_compression:
                    zip_file.writestr(zip_info, File.decompress(filedata))
                else:
                    zip_file.writestr(zip_info, filedata)
        
        zip_buffer.seek(0)

        return zip_buffer

