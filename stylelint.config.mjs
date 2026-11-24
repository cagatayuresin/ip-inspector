/** @type {import("stylelint").Config} */
export default {
  extends: ["stylelint-config-standard"],
  rules: {
    "selector-class-pattern": null,
    "custom-property-pattern": null,
    "value-keyword-case": ["lower", { ignoreProperties: ["/^--(sans|mono)$/"] }],
  },
};
