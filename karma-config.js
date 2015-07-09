// Karma configuration
// Generated on Sun Jun 14 2015 17:48:07 GMT+0200 (CEST)

module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',


    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['jasmine'],


    // list of files / patterns to load in the browser
    files: [
      'build/**/*.js',
      'libs/**/*.js',
      'test/**/*.test.js',
      'bower_components/cryptojslib/components/core.js',
      'bower_components/cryptojslib/components/cipher-core.js',
      'bower_components/cryptojslib/components/mode-ecb.js',
      'bower_components/cryptojslib/components/aes.js',
      'bower_components/cryptojslib/components/pad-nopadding.js',
      'bower_components/cryptojslib/components/sha256.js',

      // note, that karma ships with a whitelist of file extensions that are treated as binary files.
      // .kdbx is not one of them, therefore the file must have one of the extensions that are whitelisted
      // (.dat being one of them). See https://github.com/karma-runner/karma/issues/1070
      { pattern: 'test/**/*.dat', watched: true, included: false, served: true }
    ],


    // list of files to exclude
    exclude: [
      '**/*-min.js'
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
    },


    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['progress'],


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
    singleRun: false
  });
};
