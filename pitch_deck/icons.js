const React = require('react');
const ReactDOMServer = require('react-dom/server');
const sharp = require('sharp');
const fs = require('fs');
const {
  FiShield, FiAlertTriangle, FiCpu, FiGitBranch, FiSearch,
  FiLayers, FiUsers, FiTrendingUp, FiCheckCircle, FiTarget,
  FiZap, FiGlobe, FiLock, FiCode, FiBarChart2, FiDollarSign,
  FiPackage, FiServer, FiAward, FiFlag,
} = require('react-icons/fi');

const ICONS = {
  shield: FiShield, alert: FiAlertTriangle, cpu: FiCpu, branch: FiGitBranch,
  search: FiSearch, layers: FiLayers, users: FiUsers, trend: FiTrendingUp,
  check: FiCheckCircle, target: FiTarget, zap: FiZap, globe: FiGlobe,
  lock: FiLock, code: FiCode, chart: FiBarChart2, dollar: FiDollarSign,
  package: FiPackage, server: FiServer, award: FiAward, flag: FiFlag,
};

async function render(name, color, outPath, size = 256) {
  const Icon = ICONS[name];
  const svg = ReactDOMServer.renderToStaticMarkup(
    React.createElement(Icon, { color, size, strokeWidth: 1.6 })
  );
  const full = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${size}" height="${size}">${svg.match(/<svg[^>]*>([\s\S]*)<\/svg>/)[1]}</svg>`;
  await sharp(Buffer.from(full)).resize(size, size).png().toFile(outPath);
}

async function main() {
  fs.mkdirSync('icons', { recursive: true });
  const jobs = [
    ['shield', 'FFFFFF'], ['alert', 'FFFFFF'], ['cpu', 'FFFFFF'], ['branch', 'FFFFFF'],
    ['search', 'FFFFFF'], ['layers', 'FFFFFF'], ['users', 'FFFFFF'], ['trend', 'FFFFFF'],
    ['check', 'FFFFFF'], ['target', 'FFFFFF'], ['zap', 'FFFFFF'], ['globe', 'FFFFFF'],
    ['lock', 'FFFFFF'], ['code', 'FFFFFF'], ['chart', 'FFFFFF'], ['dollar', 'FFFFFF'],
    ['package', 'FFFFFF'], ['server', 'FFFFFF'], ['award', 'FFFFFF'], ['flag', 'FFFFFF'],
    // dark variants for light backgrounds
    ['shield', '0F1720', 'shield_dark'], ['alert', '0F1720', 'alert_dark'],
    ['cpu', '0F1720', 'cpu_dark'], ['branch', '0F1720', 'branch_dark'],
    ['search', '0F1720', 'search_dark'], ['layers', '0F1720', 'layers_dark'],
    ['users', '0F1720', 'users_dark'], ['trend', '0F1720', 'trend_dark'],
    ['check', '0F1720', 'check_dark'], ['target', '0F1720', 'target_dark'],
    ['zap', '0F1720', 'zap_dark'], ['globe', '0F1720', 'globe_dark'],
    ['lock', '0F1720', 'lock_dark'], ['code', '0F1720', 'code_dark'],
    ['chart', '0F1720', 'chart_dark'], ['dollar', '0F1720', 'dollar_dark'],
    ['package', '0F1720', 'package_dark'], ['server', '0F1720', 'server_dark'],
    ['award', '0F1720', 'award_dark'], ['flag', '0F1720', 'flag_dark'],
    // accent (cyan) variants
    ['shield', '35C5E3', 'shield_accent'], ['cpu', '35C5E3', 'cpu_accent'],
    ['trend', '35C5E3', 'trend_accent'], ['check', '35C5E3', 'check_accent'],
    ['target', '35C5E3', 'target_accent'],
  ];
  for (const [name, color, alias] of jobs) {
    await render(name, color, `icons/${alias || name}.png`);
  }
  console.log('rendered', jobs.length, 'icons');
}
main();
