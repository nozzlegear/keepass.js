var gulp = require('gulp');
var ts = require('gulp-typescript');
var bump = require('gulp-bump');
var run = require('gulp-run');
var del = require('del');
var yargs = require('yargs');
var runSequence = require('run-sequence');

var bowerRepository = '../keepass.js-bower';
var buildOutputDir = 'dist';

gulp.task('compile-ts', function () {

    var tsProject = ts.createProject('src/tsconfig.json', {
        typescript: require('typescript')
    });
    
    var tsResult = tsProject.src()
        .pipe(ts(tsProject));

    tsResult.dts.pipe(gulp.dest(buildOutputDir));
    return tsResult.js.pipe(gulp.dest(buildOutputDir));
});

gulp.task('watch', ['compile-ts'], function () {
    gulp.watch('src/**/*.ts', ['compile-ts']);
});

gulp.task('clean-dist', function (cb) {
    del([buildOutputDir], cb);
});

gulp.task('clean-bower-repo', function (cb) {
    del([buildOutputDir], { cwd: bowerRepository }, cb);
});

gulp.task('bump-version', function () {
    var argv = yargs.argv;
    return gulp.src(['package.json', 'bower.json'])
        .pipe(bump({ type: argv.type, version: argv.version }))
        .pipe(gulp.dest('.'));
});

gulp.task('copy-to-bower-repository', function () {
    return gulp.src(['bower.json', buildOutputDir + '/**/*'], { base: '.' })
        .pipe(gulp.dest(bowerRepository + '/'));
});

gulp.task('git-commit-bower-repo', function () {
    return gitCommit({ cwd: bowerRepository });
});

gulp.task('git-commit', function () {
    return gitCommit();
});

function gitCommit (runOpts) {
    var version = require('./package.json').version;
    
    var commands = [
        'git add -A',
        'git commit -m "Release v' + version + '"',
        'git tag v' + version
    ];
    
    if (yargs.argv.push) {
        commands.push('git push --tags');
    }
    
    // use gulp-run instead of gulp-git because gulp-git crashes the node process on my machine
    return run(commands.join(' && '), runOpts).exec();
}

/** 
 * gulp release --type=major|minor|patch|prerelease
 *              --version=1.3.4
 *              --push
 */
gulp.task('release', function (cb) {
    runSequence('clean-dist', 'clean-bower-repo', 'compile-ts', 'bump-version', 'copy-to-bower-repository', 'git-commit-bower-repo', 'git-commit', cb);
});

gulp.task('default', ['compile-ts']);
