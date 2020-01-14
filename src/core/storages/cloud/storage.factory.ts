import { FtpStorageAdapter } from './adapters/ftp.storage.adapter';
import { AwsStorageAdapter } from './adapters/aws.storage.adapter';
import { IUploadImage } from '../interfaces/upload.image.interface';
import config, { TYPE_STORAGE } from '../../../config/storage';

export class StorageFactory {
  static createStorageFromType(type: string): IUploadImage {
    switch (type) {
      case TYPE_STORAGE.FTP:
        return new FtpStorageAdapter({
          fileFilter(req, file, cb) {
            if (!config.ALLOW_AVATAR_FILE.includes(file.mimetype)) {
              return cb(
                new Error(
                  `Only ${config.ALLOW_AVATAR_FILE.join(', ')} are allowed.`,
                ),
                false,
              );
            }

            cb(null, true);
          },
        });
      case TYPE_STORAGE.AWS: {
        return new AwsStorageAdapter({
          fileFilter(req, file, cb) {
            if (!config.ALLOW_AVATAR_FILE.includes(file.mimetype)) {
              return cb(
                new Error(
                  `Only ${config.ALLOW_AVATAR_FILE.join(', ')} are allowed.`,
                ),
                false,
              );
            }

            cb(null, true);
          },
        });
      }
      default:
        return null;
    }
  }
}
