var gulp = require('gulp');
var ts = require('gulp-typescript');

gulp.task('compile-ts', function () {

    var tsProject = ts.createProject('src/tsconfig.json', {
        typescript: require('typescript')    
    });
    
    var tsResult = tsProject.src()
        .pipe(ts(tsProject));

    return tsResult.js.pipe(gulp.dest('build'));
});

gulp.task('watch', ['compile-ts'], function () {
     gulp.watch('src/**/*.ts', ['compile-ts']);
});

gulp.task('default', ['compile-ts']);
