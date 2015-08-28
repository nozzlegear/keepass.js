// Karma configuration
// Generated on Sun Jun 14 2015 17:48:07 GMT+0200 (CEST)

module.exports = function(config) {
  var configuration = {

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',


    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['systemjs', 'jasmine'],


    // list of files / patterns to load in the browser
    files: [
      'libs/**/*.js',

      // note, that karma ships with a whitelist of file extensions that are treated as binary files.
      // .kdbx is not one of them, therefore the file must have one of the extensions that are whitelisted
      // (.dat being one of them). See https://github.com/karma-runner/karma/issues/1070
      { pattern: 'test/**/*.dat', watched: true, included: false, served: true }
    ],

    systemjs: {
      files: [
        'src/**/*.js',
        'test/**/*.js'
      ],
      config: {
        transpiler: null, // disable additional transpiling, karma-babel-preprocessor already does this
        paths: {
          'systemjs': 'node_modules/systemjs/dist/system.js',
          'system-polyfills': 'node_modules/systemjs/dist/system-polyfills.js',
          'es6-module-loader': 'node_modules/es6-module-loader/dist/es6-module-loader.js'
        }
      }
    },


    // list of files to exclude
    exclude: [
      '**/*-min.js'
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      'src/**/*.js': ['babel', 'coverage'],
      'test/**/*.js': ['babel']
    },

    babelPreprocessor: {
      options: {
        auxiliaryCommentBefore: 'istanbul ignore next'
      }
    },

    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['progress', 'coverage'],
    
    coverageReporter: {
      reporters: [
        {type: "lcov", dir: "coverage"},
        {type: "text"},
        {type: "text-summary"}
      ]
    },

    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,


    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,


    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ['Chrome', 'Firefox'],


    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: false,
    
    customLaunchers: {
        Chrome_travis_ci: {
            base: 'Chrome',
            flags: ['--no-sandbox']
        }
    }
  };
  
  if (process.env.TRAVIS) {
    configuration.browsers = ['Chrome_travis_ci'];
    configuration.singleRun = true;
    
    // Disable testing with Chrome in Travis for now because Travis ships with
    // Chrome 37, but we are using APIs that exist in newer versions of Chrome 
    configuration.browsers = ['Firefox'];
  }

  config.set(configuration);
};
