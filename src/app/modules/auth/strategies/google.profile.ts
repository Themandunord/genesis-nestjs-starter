export interface GoogleProfile {
  id: string;
  displayName: string;
  name: { familyName: string; givenName: string };
  emails: [{ value: string; type: string }];
  photos: [{ value: string }];
  gender: string;
  provider: string;
  _raw: string;
  _json: {
    kind: string;
    etag: string;
    gender: string;
    emails: [{ value: string; type: string }];
    objectType: 'person';
    id: string;
    displayName: string;
    name: { familyName: string; givenName: string };
    url: string;
    image: {
      url: string;
      isDefault: boolean;
    };
    isPlusUser: boolean;
    language: string;
    circledByCount: number;
    verified: boolean;
  };
}
