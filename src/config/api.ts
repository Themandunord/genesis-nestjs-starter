export default {
  name: process.env.NAME,
  port: +process.env.API_PORT,
  domain: process.env.DOMAIN,
  host: process.env.HOST,
  web: process.env.WEB,
  confirmPath: process.env.CONFIRM_PATH,
  forgetPath: process.env.FORGOT_PASSWORD_PATH,
  isSecure: process.env.IS_SECURE === 'true',
  secret: process.env.APP_SECRET,
  environment: process.env.NODE_ENV,
  // helpers
  isProduction() {
    return this.get('api.environment') === 'production';
  },
  protocol() {
    return this.get('api.isSecure') ? 'https' : 'http';
  },
  webUrl() {
    return `${this.get('api').protocol()}://${this.get('api.web')}`;
  },
  apiUrl() {
    return `${this.get('api').protocol()}://${this.get('api.host')}`;
  },
  confirmUrl() {
    return `${this.get('api').webUrl()}${this.get('api.confirmPath')}`;
  },
  forgetUrl() {
    return `${this.get('api').webUrl()}${this.get('api.forgetPath')}`;
  },
};
