export default {
  transport: {
    host: process.env.MAILER_HOST,
    port: +process.env.MAILER_PORT,
    secure: process.env.MAILER_SECURE === 'true',
    auth: {
      user: process.env.MAILER_USER,
      pass: process.env.MAILER_PASS,
    },
  },
  defaults: {
    forceEmbeddedImages: true,
    from: '"Genesis" <info@genesis.com>',
  },
  templateDir: './templates/dist',
};
