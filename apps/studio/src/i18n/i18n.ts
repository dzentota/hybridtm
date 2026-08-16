import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

const LANGUAGE_KEY = 'hybridtm.studio.language'

const resources = {
  en: {
    translation: {
      login: {
        title: 'HybridTM Studio',
        email: 'Email',
        password: 'Password',
        signIn: 'Sign in',
        signingIn: 'Signing in…',
        invalid: 'Invalid email or password.',
      },
      palette: {
        search: 'Search components…',
        loading: 'Loading knowledge base…',
        addAria: 'Add {{name}} to canvas',
        rules: '{{count}} rule',
        rules_other: '{{count}} rules',
      },
      toolbar: {
        title: 'Model title',
        undo: 'Undo (Ctrl+Z)',
        undoShort: 'Undo',
        redo: 'Redo (Ctrl+Shift+Z)',
        redoShort: 'Redo',
        autoLayout: 'Auto-layout',
        layingOut: 'Laying out…',
        overlay: 'Overlay:',
        overlayRisks: 'Risks',
        overlayData: 'Data',
        overlayExposure: 'Exposure',
        overlayCoverage: 'Coverage',
        exportPng: 'PNG',
        exportSvg: 'SVG',
        language: 'Language',
        notSaved: 'Not saved yet',
        savedNow: 'Saved just now',
        savedSecondsAgo: 'Saved {{count}}s ago',
        savedMinutesAgo: 'Saved {{count}}m ago',
      },
      findings: {
        runAnalysis: 'Run analysis',
        analyzing: 'Analyzing…',
        minSeverity: 'min severity: {{severity}}',
        empty: 'No findings yet — run analysis to check the model.',
      },
      autosave: {
        found: 'Unsaved changes from a previous session were found (saved {{time}}).',
        restore: 'Restore',
        discard: 'Discard',
      },
      command: {
        placeholder: 'Type a command…',
        empty: 'No matching commands',
      },
      inspector: {
        empty: 'Select a component to inspect its properties.',
      },
      canvasBanner: 'HybridTM Studio — drag a component from the palette onto the canvas',
    },
  },
  ru: {
    translation: {
      login: {
        title: 'HybridTM Studio',
        email: 'Эл. почта',
        password: 'Пароль',
        signIn: 'Войти',
        signingIn: 'Выполняется вход…',
        invalid: 'Неверный email или пароль.',
      },
      palette: {
        search: 'Поиск компонентов…',
        loading: 'Загрузка базы знаний…',
        addAria: 'Добавить «{{name}}» на холст',
        rules_one: '{{count}} правило',
        rules_few: '{{count}} правила',
        rules_many: '{{count}} правил',
        rules_other: '{{count}} правила',
      },
      toolbar: {
        title: 'Название модели',
        undo: 'Отменить (Ctrl+Z)',
        undoShort: 'Отменить',
        redo: 'Повторить (Ctrl+Shift+Z)',
        redoShort: 'Повторить',
        autoLayout: 'Авторазметка',
        layingOut: 'Разметка…',
        overlay: 'Слой:',
        overlayRisks: 'Риски',
        overlayData: 'Данные',
        overlayExposure: 'Экспозиция',
        overlayCoverage: 'Покрытие',
        exportPng: 'PNG',
        exportSvg: 'SVG',
        language: 'Язык',
        notSaved: 'Ещё не сохранено',
        savedNow: 'Сохранено только что',
        savedSecondsAgo: 'Сохранено {{count}} с назад',
        savedMinutesAgo: 'Сохранено {{count}} мин назад',
      },
      findings: {
        runAnalysis: 'Запустить анализ',
        analyzing: 'Анализ…',
        minSeverity: 'мин. серьёзность: {{severity}}',
        empty: 'Пока нет находок — запустите анализ модели.',
      },
      autosave: {
        found: 'Найдены несохранённые изменения из предыдущей сессии (сохранено {{time}}).',
        restore: 'Восстановить',
        discard: 'Отклонить',
      },
      command: {
        placeholder: 'Введите команду…',
        empty: 'Нет подходящих команд',
      },
      inspector: {
        empty: 'Выберите компонент, чтобы посмотреть его свойства.',
      },
      canvasBanner: 'HybridTM Studio — перетащите компонент из палитры на холст',
    },
  },
}

void i18n.use(initReactI18next).init({
  resources,
  lng: localStorage.getItem(LANGUAGE_KEY) ?? 'en',
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
})

i18n.on('languageChanged', (lng) => localStorage.setItem(LANGUAGE_KEY, lng))

export default i18n
